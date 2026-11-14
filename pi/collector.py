"""
USB Serial Collector / Gateway for the Arduino nodes.
Runs on the Raspberry Pi. Reads JSON telemetry lines from both Arduinos, stores
them in SQLite, publishes them to MQTT (so the laptop can monitor the network),
and handles RFID access decisions (shown on the room node's LCD).
Also supports a mock mode for local testing without hardware.
"""

import os
import json
import time
import sqlite3
import random
import argparse
import threading
from datetime import datetime, timezone

try:
    import serial
except ImportError:
    serial = None

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

DB_PATH = "data/telemetry.db"
ALLOWED_UIDS_PATH = "data/allowed_uids.txt"
DEFAULT_PORTS = [
    "/dev/ttyACM0",
    "/dev/ttyACM1",
]
BAUD = 9600
LCD_DEVICE = "arduino_1"

# Filled in at runtime: open serial port per device (to send LCD messages back),
# and the MQTT client (None when publishing is off).
ports_by_device = {}
mqtt_client = None
db_lock = threading.Lock()


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path=DB_PATH):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            device TEXT,
            event TEXT,
            payload TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def store_reading(device, event, payload_dict, db_path=DB_PATH):
    received = get_timestamp()
    with db_lock:
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO telemetry (received_at, device, event, payload)
            VALUES (?, ?, ?, ?)
        """, (
            received,
            device,
            event,
            json.dumps(payload_dict)
        ))
        conn.commit()
        conn.close()
    return received


def publish(device, event, payload_dict):
    if mqtt_client is not None:
        mqtt_client.publish(f"iot/{device}/{event}", json.dumps(payload_dict))


def record(device, event, payload_dict, db_path=DB_PATH):
    ts = store_reading(device, event, payload_dict, db_path)
    publish(device, event, payload_dict)
    return ts


def load_allowed_uids(path=ALLOWED_UIDS_PATH):
    """One card UID per line (hex, as printed by the door node). Lines starting with # are ignored."""
    try:
        with open(path) as f:
            return {line.strip().upper() for line in f if line.strip() and not line.startswith("#")}
    except FileNotFoundError:
        return set()


def show_on_lcd(line1, line2=""):
    port = ports_by_device.get(LCD_DEVICE)
    if port is None:
        print(f"[LCD] (room node not connected) {line1} | {line2}")
        return
    try:
        port.write(f"LCD:{line1[:16]}|{line2[:16]}\n".encode("ascii", errors="replace"))
    except Exception as e:
        print(f"[LCD] Write failed: {e}")


def handle_rfid_scan(data, db_path=DB_PATH):
    uid = str(data.get("uid", "")).upper()
    granted = uid in load_allowed_uids()
    event = "access_granted" if granted else "access_denied"
    device = data.get("device", "unknown")
    # Timestamp keeps repeat scans of the same card from looking like MQTT replays.
    record(device, event, {"device": device, "event": event, "uid": uid, "at": get_timestamp()}, db_path)
    show_on_lcd("Access granted" if granted else "Access denied", uid)
    print(f"[Access] {uid} -> {event}")


def handle_line(line, port_name, ser=None, db_path=DB_PATH):
    try:
        data = json.loads(line)
    except ValueError:
        data = None
    # A half-received line after a board reset can still parse (e.g. "240"), so require an object.
    if not isinstance(data, dict):
        print(f"[{port_name}] Invalid JSON line received: {line}")
        return

    device = data.get("device", "unknown")
    event = data.get("event", "sensor_reading")
    if ser is not None:
        ports_by_device[device] = ser

    ts = record(device, event, data, db_path)
    print(f"[{ts}] [{port_name}] {device} -> {data}")

    if event == "rfid_scan":
        handle_rfid_scan(data, db_path)


def collect_serial(port, db_path=DB_PATH):
    if serial is None:
        print("Error: pyserial is not installed. Run 'pip install pyserial'")
        return

    print(f"Starting serial collector thread for {port} at {BAUD} baud...")
    while True:
        try:
            with serial.Serial(port, BAUD, timeout=2) as ser:
                print(f"[Collector] Connected to {port}")
                while True:
                    line = ser.readline().decode("utf-8", errors="ignore").strip()
                    if line:
                        handle_line(line, port, ser, db_path)

        except Exception as e:
            for device, s in list(ports_by_device.items()):
                if s.port == port:
                    del ports_by_device[device]
            print(f"[Collector] Error on {port}: {e}. Retrying in 3 seconds...")
            time.sleep(3)


def simulate_node(device_name, interval_sec=1.0, db_path=DB_PATH):
    """Generates synthetic baseline telemetry for testing on machines without physical Arduinos."""
    print(f"[Sim] Started simulator for {device_name} (interval {interval_sec}s)...")
    record(device_name, "boot", {"device": device_name, "event": "boot"}, db_path)

    mq135_base = 220.0
    distance_base = 45.0

    while True:
        uptime = int(time.time() * 1000)
        if device_name == "arduino_1":
            ir_count = 1 if random.random() < 0.05 else 0
            payload = {
                "device": "arduino_1",
                "event": "sensor_reading",
                "mq135_raw": int(max(50, min(1023, mq135_base + random.gauss(0, 4)))),
                "distance_cm": round(max(5.0, distance_base + random.gauss(0, 1.2)), 2),
                "ir": ir_count,
                "ir_count": ir_count,
                "uptime_ms": uptime
            }
        else:
            payload = {
                "device": "arduino_2",
                "event": "sensor_reading",
                "motion": 1 if random.random() < 0.15 else 0,
                "rfid_ok": 1,
                "uptime_ms": uptime
            }

        ts = record(device_name, "sensor_reading", payload, db_path)
        print(f"[SIM-{ts}] {device_name} -> {payload}")
        time.sleep(interval_sec)


def connect_mqtt(host, port):
    global mqtt_client
    if mqtt is None:
        print("Error: paho-mqtt is not installed. Run 'pip install paho-mqtt'")
        return
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="gateway_pi")
    client.connect(host, port, 60)
    client.loop_start()  # background thread; reconnects automatically
    mqtt_client = client
    print(f"[MQTT] Publishing to {host}:{port} under iot/<device>/<event>")


def main():
    parser = argparse.ArgumentParser(description="IoT Telemetry Collector / Gateway")
    parser.add_argument("--ports", nargs="+", default=DEFAULT_PORTS, help="Serial ports to listen on")
    parser.add_argument("--db", default=DB_PATH, help="SQLite database path")
    parser.add_argument("--mock", action="store_true", help="Run in mock/simulation mode without hardware")
    parser.add_argument("--mqtt-host", help="MQTT broker to publish to (e.g. localhost on the Pi). Omit to disable.")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port")
    args = parser.parse_args()

    init_db(args.db)
    if args.mqtt_host:
        connect_mqtt(args.mqtt_host, args.mqtt_port)

    if args.mock:
        print("=== RUNNING IN MOCK / SIMULATION MODE ===")
        for name in ("arduino_1", "arduino_2"):
            threading.Thread(target=simulate_node, args=(name, 1.0, args.db), daemon=True).start()
    else:
        for port in args.ports:
            threading.Thread(target=collect_serial, args=(port, args.db), daemon=True).start()

    print("Collector running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCollector stopped gracefully.")


if __name__ == "__main__":
    main()
