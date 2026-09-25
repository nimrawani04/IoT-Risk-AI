/*
 * Node 2: Environmental Node
 * Hardware: Arduino Uno + MQ-4 Gas Sensor (A0) + HC-SR04 Ultrasonic (TRIG=D3, ECHO=D4)
 *
 * Sends JSON formatted telemetry over Serial (9600 baud).
 */

const int MQ4_PIN = A0;
const int TRIG_PIN = 3;
const int ECHO_PIN = 4;

unsigned long lastSend = 0;
const unsigned long SEND_INTERVAL = 1000;

float readDistanceCm() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);

  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  unsigned long duration = pulseIn(ECHO_PIN, HIGH, 30000);

  if (duration == 0) {
    return -1.0;
  }

  return duration * 0.0343 / 2.0;
}

void setup() {
  Serial.begin(9600);

  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  Serial.println("{\"device\":\"arduino_2\",\"event\":\"boot\"}");
}

void loop() {
  unsigned long now = millis();

  int mq4Raw = analogRead(MQ4_PIN);
  float distance = readDistanceCm();

  if (now - lastSend >= SEND_INTERVAL) {
    lastSend = now;

    Serial.print("{\"device\":\"arduino_2\",");
    Serial.print("\"event\":\"sensor_reading\",");
    Serial.print("\"mq4_raw\":");
    Serial.print(mq4Raw);
    Serial.print(",\"distance_cm\":");
    Serial.print(distance, 2);
    Serial.print(",\"uptime_ms\":");
    Serial.print(now);
    Serial.println("}");
  }
}
