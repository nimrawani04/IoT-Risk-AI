/*
 * Arduino 2: Door node
 * PIR (OUT D8), RC522 RFID (SDA/SS D10, SCK D13, MOSI D11, MISO D12, RST D9).
 * RC522 VCC goes to 3.3V, NOT 5V.
 * Library: MFRC522 (GithubCommunity) from the Library Manager.
 *
 * Sends one JSON line per second over USB serial (9600 baud), plus an
 * "rfid_scan" line the moment a card is read. The Pi decides granted/denied.
 */

#include <SPI.h>
#include <MFRC522.h>

const int PIR_PIN = 8;
const int RFID_SS = 10;
const int RFID_RST = 9;

MFRC522 rfid(RFID_SS, RFID_RST);

const unsigned long SEND_INTERVAL = 1000;
unsigned long lastSend = 0;
int motionSeen = 0;  // motion at any point since the last send
int lastRfidOk = 0;  // reader state at the last check, to spot it coming back

void setup() {
  Serial.begin(9600);
  pinMode(PIR_PIN, INPUT);
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

  if (digitalRead(PIR_PIN) == HIGH) motionSeen = 1;

  unsigned long now = millis();
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

  Serial.print("{\"device\":\"arduino_2\",\"event\":\"sensor_reading\",\"motion\":");
  Serial.print(motionSeen);
  Serial.print(",\"rfid_ok\":");
  Serial.print(rfidOk);
  Serial.print(",\"uptime_ms\":");
  Serial.print(now);
  Serial.println("}");
  motionSeen = 0;
}
