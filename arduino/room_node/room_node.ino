/*
 * Arduino 1: Room node
 * PIR motion sensor inside the room (OUT D8), MQ-135 gas sensor (AO A0).
 *
 * Sends one JSON line per second over USB serial (9600 baud).
 * motion = 1 if the PIR saw movement at any point during that second. The Pi
 * uses it to confirm that someone who entered through the door is really inside.
 *
 * The PIR needs 30-60 s after power-on to settle; early readings can be noise.
 */

const int PIR_PIN = 8;
const int MQ135_PIN = A0;

const unsigned long SEND_INTERVAL = 1000;
unsigned long lastSend = 0;
int motionSeen = 0;  // motion at any point since the last send

void setup() {
  Serial.begin(9600);
  pinMode(PIR_PIN, INPUT);
  Serial.println("{\"device\":\"arduino_1\",\"event\":\"boot\"}");
}

void loop() {
  if (digitalRead(PIR_PIN) == HIGH) motionSeen = 1;

  unsigned long now = millis();
  if (now - lastSend < SEND_INTERVAL) return;
  lastSend = now;

  Serial.print("{\"device\":\"arduino_1\",\"event\":\"sensor_reading\",\"mq135_raw\":");
  Serial.print(analogRead(MQ135_PIN));
  Serial.print(",\"motion\":");
  Serial.print(motionSeen);
  Serial.print(",\"uptime_ms\":");
  Serial.print(now);
  Serial.println("}");
  motionSeen = 0;
}
