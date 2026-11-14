/*
 * Arduino 1: Room node
 * HC-SR04 (TRIG D3, ECHO D4), IR sensor (OUT D7), MQ-135 (AO A0),
 * 16x2 I2C LCD (SDA A4, SCL A5).
 * Library: LiquidCrystal_I2C (Frank de Brabander) from the Library Manager.
 *
 * Sends one JSON line per second over USB serial (9600 baud).
 * Accepts "LCD:<line1>|<line2>" lines from the Pi and shows them for 3 s.
 */

#include <Wire.h>
#include <LiquidCrystal_I2C.h>

const int TRIG_PIN = 3;
const int ECHO_PIN = 4;
const int IR_PIN = 7;
const int MQ135_PIN = A0;

// Most I2C backpacks use 0x27, some 0x3F. If the screen stays blank, try 0x3F.
LiquidCrystal_I2C lcd(0x27, 16, 2);

const unsigned long SEND_INTERVAL = 1000;
const unsigned long MESSAGE_HOLD = 3000;
unsigned long lastSend = 0;
unsigned long messageUntil = 0;

int lastIr = 0;
unsigned int irCount = 0;  // beam breaks since the last send
String rxLine;

float readOnceCm() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  unsigned long duration = pulseIn(ECHO_PIN, HIGH, 30000);
  if (duration == 0) {
    return -1.0;  // no echo: out of range or sensor fault
  }
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

void setup() {
  Serial.begin(9600);
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  pinMode(IR_PIN, INPUT);

  lcd.init();
  lcd.backlight();
  showLine(0, "Room node");
  showLine(1, "Starting...");

  Serial.println("{\"device\":\"arduino_1\",\"event\":\"boot\"}");
}

void loop() {
  handleSerial();

  // Most IR obstacle modules pull OUT low when something is in front of them.
  int ir = digitalRead(IR_PIN) == LOW ? 1 : 0;
  if (ir && !lastIr) irCount++;
  lastIr = ir;

  unsigned long now = millis();
  if (now - lastSend < SEND_INTERVAL) return;
  lastSend = now;

  // Read slow sensors once per second so pulseIn() doesn't block IR edge counting.
  int mq135 = analogRead(MQ135_PIN);
  float distance = readDistanceCm();

  Serial.print("{\"device\":\"arduino_1\",\"event\":\"sensor_reading\",\"mq135_raw\":");
  Serial.print(mq135);
  Serial.print(",\"distance_cm\":");
  Serial.print(distance, 2);
  Serial.print(",\"ir\":");
  Serial.print(ir);
  Serial.print(",\"ir_count\":");
  Serial.print(irCount);
  Serial.print(",\"uptime_ms\":");
  Serial.print(now);
  Serial.println("}");
  irCount = 0;

  if ((long)(now - messageUntil) >= 0) {
    showLine(0, "Gas " + String(mq135));
    showLine(1, "Dist " + String(distance, 1) + " cm");
  }
}
