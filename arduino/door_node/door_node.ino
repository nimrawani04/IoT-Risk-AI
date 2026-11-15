/*
 * Arduino 2: Door node
 * RC522 RFID (SDA/SS D10, SCK D13, MOSI D11, MISO D12, RST D9, VCC 3.3V - NOT 5V),
 * IR obstacle sensor at the doorway (OUT D7),
 * HC-SR04 outside the door facing the corridor (TRIG D3, ECHO D4),
 * 16x2 I2C LCD next to the reader (SDA A4, SCL A5).
 * Libraries: MFRC522 (GithubCommunity), LiquidCrystal_I2C (Frank de Brabander).
 *
 * Sends one JSON line per second over USB serial (9600 baud), plus an
 * "rfid_scan" line the moment a card is read. The Pi decides granted/denied
 * and sends "LCD:<line1>|<line2>" back, shown for 3 s.
 *
 * Direction: the ultrasonic sees the corridor side. Someone close to it BEFORE
 * the IR beam breaks is entering; close to it right AFTER is leaving. The Pi
 * works that out from distance_cm and ir_count.
 */

#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

const int RFID_SS = 10;
const int RFID_RST = 9;
const int IR_PIN = 7;
const int TRIG_PIN = 3;
const int ECHO_PIN = 4;

MFRC522 rfid(RFID_SS, RFID_RST);
// Most I2C backpacks use 0x27, some 0x3F. If the screen stays blank, try 0x3F.
LiquidCrystal_I2C lcd(0x27, 16, 2);

const unsigned long SEND_INTERVAL = 1000;
const unsigned long MESSAGE_HOLD = 3000;
unsigned long lastSend = 0;
unsigned long messageUntil = 0;
int lastRfidOk = 0;  // reader state at the last check, to spot it coming back
String rxLine;

// IR obstacle modules flicker at the edge of their range. Count a crossing only when the
// beam has been steadily blocked for IR_STABLE_MS, and at most one per IR_LOCKOUT_MS.
const unsigned long IR_STABLE_MS = 50;
const unsigned long IR_LOCKOUT_MS = 700;
int irRaw = 0, irStable = 0;
unsigned long irChangedAt = 0, lastCrossingAt = 0;
unsigned int irCount = 0;  // crossings since the last send

float readOnceCm() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  unsigned long duration = pulseIn(ECHO_PIN, HIGH, 30000);
  if (duration == 0) return -1.0;  // no echo: out of range or sensor fault
  return duration * 0.0343 / 2.0;
}

// Median of 3 pings: one stray echo (e.g. off a side wall) can't swing the reading.
float readDistanceCm() {
  float a = readOnceCm();
  delay(30);  // let the previous ping's echoes die out
  float b = readOnceCm();
  delay(30);
  float c = readOnceCm();
  return max(min(a, b), min(max(a, b), c));
}

void showLine(int row, String text) {
  text = text.substring(0, 16);
  lcd.setCursor(0, row);
  lcd.print(text);
  for (int i = text.length(); i < 16; i++) lcd.print(' ');
}

void handleSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') {
      rxLine.trim();
      if (rxLine.startsWith("LCD:")) {
        int sep = rxLine.indexOf('|');
        showLine(0, sep < 0 ? rxLine.substring(4) : rxLine.substring(4, sep));
        showLine(1, sep < 0 ? "" : rxLine.substring(sep + 1));
        messageUntil = millis() + MESSAGE_HOLD;
      }
      rxLine = "";
    } else if (rxLine.length() < 64) {
      rxLine += c;
    }
  }
}

void updateIr(unsigned long now) {
  // Most IR obstacle modules pull OUT low when something is in front of them.
  int raw = digitalRead(IR_PIN) == LOW ? 1 : 0;
  if (raw != irRaw) { irRaw = raw; irChangedAt = now; }
  if (raw != irStable && now - irChangedAt >= IR_STABLE_MS) {
    irStable = raw;
    if (irStable && now - lastCrossingAt >= IR_LOCKOUT_MS) { irCount++; lastCrossingAt = now; }
  }
}

void setup() {
  Serial.begin(9600);
  pinMode(IR_PIN, INPUT);
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  lcd.init();
  lcd.backlight();
  showLine(0, "Door node");
  showLine(1, "Starting...");

  SPI.begin();
  rfid.PCD_Init();
  // Default gain is weak on many clone boards; max gain lets cards read from a few cm away.
  rfid.PCD_SetAntennaGain(rfid.RxGain_max);

  // Version tells genuine (0x91/0x92) from clone chips (0x88, 0x12, 0xB2) when debugging.
  Serial.print("{\"device\":\"arduino_2\",\"event\":\"boot\",\"rfid_version\":");
  Serial.print(rfid.PCD_ReadRegister(MFRC522::VersionReg));
  Serial.println("}");
}

void loop() {
  handleSerial();
  unsigned long now = millis();
  updateIr(now);

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    Serial.print("{\"device\":\"arduino_2\",\"event\":\"rfid_scan\",\"uid\":\"");
    for (byte i = 0; i < rfid.uid.size; i++) {
      if (rfid.uid.uidByte[i] < 0x10) Serial.print('0');
      Serial.print(rfid.uid.uidByte[i], HEX);
    }
    Serial.print("\",\"uptime_ms\":");
    Serial.print(millis());
    Serial.println("}");
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
  }

  if (now - lastSend < SEND_INTERVAL) return;
  lastSend = now;

  // 0x00 or 0xFF means the reader isn't answering on SPI (loose wire or no power).
  byte version = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  int rfidOk = (version != 0x00 && version != 0xFF) ? 1 : 0;
  // A reader that comes back after a dropout has lost its setup (antenna off), so set it up again.
  if (rfidOk && !lastRfidOk) {
    rfid.PCD_Init();
    rfid.PCD_SetAntennaGain(rfid.RxGain_max);
  }
  lastRfidOk = rfidOk;

  // Once a second, so the ~100 ms of pings doesn't hold up card reads or IR counting for long.
  float distance = readDistanceCm();
  updateIr(millis());

  Serial.print("{\"device\":\"arduino_2\",\"event\":\"sensor_reading\",\"distance_cm\":");
  Serial.print(distance, 2);
  Serial.print(",\"ir\":");
  Serial.print(irStable);
  Serial.print(",\"ir_count\":");
  Serial.print(irCount);
  Serial.print(",\"rfid_ok\":");
  Serial.print(rfidOk);
  Serial.print(",\"uptime_ms\":");
  Serial.print(now);
  Serial.println("}");
  irCount = 0;

  if ((long)(now - messageUntil) >= 0) {
    showLine(0, rfidOk ? "Scan your card" : "Reader offline");
    showLine(1, distance < 0 ? "Corridor: clear" : "Corridor " + String(distance, 0) + "cm");
  }
}
