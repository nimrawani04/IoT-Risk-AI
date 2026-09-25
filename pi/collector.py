"""
USB Serial Collector for Arduino Sensor Nodes.
Reads JSON telemetry lines from configured serial ports and stores them in SQLite.
Also supports a simulation / mock mode for local testing without physical hardware.
"""

import os
import sys
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

DB_PATH = "data/telemetry.db"
DEFAULT_PORTS = [
    "/dev/ttyACM0",
    "/dev/ttyACM1",
]
BAUD = 9600


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


def collect_serial(port, db_path=DB_PATH):
    if serial is None:
        print(f"Error: pyserial is not installed. Run 'pip install pyserial'")
        return

    print(f"Starting serial collector thread for {port} at {BAUD} baud...")
    while True:
        try:
            with serial.Serial(port, BAUD, timeout=2) as ser:
                print(f"[Collector] Connected to {port}")
                while True:
                    line = ser.readline().decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        print(f"[{port}] Invalid JSON line received: {line}")
                        continue

                    device = data.get("device", "unknown")
                    event = data.get("event", "sensor_reading")
                    ts = store_reading(device, event, data, db_path)
                    print(f"[{ts}] [{port}] {device} -> {data}")

        except Exception as e:
            print(f"[Collector] Error on {port}: {e}. Retrying in 3 seconds...")
            time.sleep(3)


def simulate_node(device_name, interval_sec=1.0, db_path=DB_PATH):
    """Generates synthetic baseline telemetry for testing on machines without physical Arduinos."""
    print(f"[Sim] Started simulator for {device_name} (interval {interval_sec}s)...")
    boot_payload = {"device": device_name, "event": "boot"}
    store_reading(device_name, "boot", boot_payload, db_path)

    mq4_base = 220.0
    distance_base = 45.0

    while True:
        uptime = int(time.time() * 1000)
        if device_name == "arduino_1":
            motion = 1 if random.random() < 0.15 else 0
            button = 1 if random.random() < 0.05 else 0
            payload = {
                "device": "arduino_1",
                "event": "sensor_reading",
                "motion": motion,
                "button": button,
                "uptime_ms": uptime
            }
        else:
            # Arduino 2
            mq4_val = int(max(50, min(1023, mq4_base + random.gauss(0, 4))))
            dist_val = round(max(5.0, distance_base + random.gauss(0, 1.2)), 2)
            payload = {
                "device": "arduino_2",
                "event": "sensor_reading",
                "mq4_raw": mq4_val,
                "distance_cm": dist_val,
                "uptime_ms": uptime
            }

        ts = store_reading(device_name, "sensor_reading", payload, db_path)
        print(f"[SIM-{ts}] {device_name} -> {payload}")
        time.sleep(interval_sec)


def main():
    parser = argparse.ArgumentParser(description="IoT Telemetry Collector")
    parser.add_argument("--ports", nargs="+", default=DEFAULT_PORTS, help="Serial ports to listen on")
    parser.add_argument("--db", default=DB_PATH, help="SQLite database path")
    parser.add_argument("--mock", action="store_true", help="Run in mock/simulation mode without hardware")
    args = parser.parse_args()

    init_db(args.db)

    if args.mock:
        print("=== RUNNING IN MOCK / SIMULATION MODE ===")
        t1 = threading.Thread(target=simulate_node, args=("arduino_1", 1.0, args.db), daemon=True)
        t2 = threading.Thread(target=simulate_node, args=("arduino_2", 1.0, args.db), daemon=True)
        t1.start()
        t2.start()
    else:
        for port in args.ports:
            thread = threading.Thread(target=collect_serial, args=(port, args.db), daemon=True)
            thread.start()

    print("Collector running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCollector stopped gracefully.")


if __name__ == "__main__":
    main()
