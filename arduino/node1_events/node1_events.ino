/*
 * Node 1: Event and Access Node
 * Hardware: Arduino Uno + PIR Sensor (D8) + Push Button (D2)
 *
 * Sends JSON formatted telemetry over Serial (9600 baud).
 */

const int PIR_PIN = 8;
const int BUTTON_PIN = 2;

unsigned long lastSend = 0;
const unsigned long SEND_INTERVAL = 1000;

void setup() {
  Serial.begin(9600);

  pinMode(PIR_PIN, INPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  Serial.println("{\"device\":\"arduino_1\",\"event\":\"boot\"}");
}

void loop() {
  unsigned long now = millis();

  int motion = digitalRead(PIR_PIN);
  int button = digitalRead(BUTTON_PIN) == LOW ? 1 : 0;

  if (now - lastSend >= SEND_INTERVAL) {
    lastSend = now;

    Serial.print("{\"device\":\"arduino_1\",");
    Serial.print("\"event\":\"sensor_reading\",");
    Serial.print("\"motion\":");
    Serial.print(motion);
    Serial.print(",\"button\":");
    Serial.print(button);
    Serial.print(",\"uptime_ms\":");
    Serial.print(now);
    Serial.println("}");
  }
}
