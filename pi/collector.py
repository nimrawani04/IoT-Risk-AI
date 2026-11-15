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


# --- Lab scenario injection (only with --allow-inject) ---------------------
# Lets experiments/auto_record.py act out faults and door scenarios remotely by
# changing real readings at the gateway, so nobody has to unplug wires or walk
# through the door. Off by default: anyone on the network could otherwise fake data.
INJECT_TOPIC = "lab/inject"
UNKNOWN_UID = "DEADBEEF"
inject = {"scenario": None, "until": 0.0, "pending_ir": 0, "presence_until": 0.0}

# Door behaviour per scenario: (allowed card?, IR passes, seconds between repeats)
DOOR_ACTIONS = {
    "normal": (True, 1, (30, 60)),
    "normal_scan_no_entry": (True, 0, (15, 30)),
    "attack_brute_force": (False, 0, (2, 4)),
    "attack_slow_brute_force": (False, 0, (6, 10)),
    "attack_tailgating": (True, 3, (20, 30)),
    "attack_break_in": (None, 1, (15, 25)),
}
# In normal use people also stand near the door without scanning (chatting, passing by).
LINGER_SCENARIOS = {"normal", "normal_scan_no_entry"}


def active_scenario():
    return inject["scenario"] if time.time() < inject["until"] else None


def on_inject(client, userdata, msg):
    try:
        cmd = json.loads(msg.payload)
        scenario = cmd.get("scenario")
        seconds = min(float(cmd.get("seconds", 0)), 3600)  # always expires, even if the laptop disappears
    except (ValueError, AttributeError, TypeError):
        print(f"[Inject] Ignored bad command: {msg.payload!r}")
        return
    inject.update(scenario=scenario, until=time.time() + seconds, pending_ir=0, presence_until=0.0)
    print(f"[Inject] {scenario or 'cleared'} for {seconds:.0f}s")


def apply_fault(data):
    """Change a real sensor_reading to look like the active fault. Returns None to drop it."""
    s, device = active_scenario(), data.get("device")
    if s and time.time() < inject["presence_until"]:
        # Someone at the door: the ultrasonic sees them and the PIR fires.
        if device == "arduino_1":
            data["distance_cm"] = round(random.uniform(35, 75), 2)
        elif device == "arduino_2":
            data["motion"] = int(random.random() < 0.85)
    if device == "arduino_1":
        if s == "fault_node_offline":
            return None
        if s == "fault_ultrasonic":
            data["distance_cm"] = -1  # what the firmware sends when no echo comes back
        if s == "fault_gas_sensor":
            # shortcut: random values stand in for a floating A0 pin; record a real unplug to compare.
            data["mq135_raw"] = random.randint(0, 1023)
        if inject["pending_ir"]:
            # One person per reading, like real people walking through one after another.
            data["ir_count"] = data.get("ir_count", 0) + 1
            data["ir"] = 1
            inject["pending_ir"] -= 1
    elif device == "arduino_2" and s == "fault_rfid":
        data["rfid_ok"] = 0
    return data


def door_actor(db_path=DB_PATH):
    """Performs card scans and IR passes for the active door scenario."""
    last, next_at, next_linger = None, 0.0, 0.0
    while True:
        s, now = active_scenario(), time.time()
        if s != last:
            last, next_at, next_linger = s, now + random.uniform(2, 5), now + random.uniform(10, 40)
        if s in LINGER_SCENARIOS and now >= next_linger:
            inject["presence_until"] = max(inject["presence_until"], now + random.uniform(5, 30))
            next_linger = now + random.uniform(40, 90)
        if s in DOOR_ACTIONS and now >= next_at:
            allowed, passes, gap = DOOR_ACTIONS[s]
            inject["presence_until"] = max(inject["presence_until"], now + random.uniform(3, 4) + passes)
            if allowed is not None:
                uid = random.choice(sorted(load_allowed_uids()) or ["613E7017"]) if allowed else UNKNOWN_UID
                # Same line the door node prints, sent through the normal path.
                handle_line(json.dumps({"device": "arduino_2", "event": "rfid_scan", "uid": uid}), "inject",
                            db_path=db_path)
            inject["pending_ir"] += passes
            next_at = now + random.uniform(*gap)
        time.sleep(0.5)


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
    if event == "sensor_reading":
        data = apply_fault(data)
        if data is None:
            return

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

        payload = apply_fault(payload)
        if payload is None:
            time.sleep(interval_sec)
            continue
        ts = record(device_name, "sensor_reading", payload, db_path)
        print(f"[SIM-{ts}] {device_name} -> {payload}")
        time.sleep(interval_sec)


def connect_mqtt(host, port, allow_inject=False):
    global mqtt_client
    if mqtt is None:
        print("Error: paho-mqtt is not installed. Run 'pip install paho-mqtt'")
        return
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="gateway_pi")
    if allow_inject:
        client.message_callback_add(INJECT_TOPIC, on_inject)
        # Subscribe in on_connect so it survives reconnects.
        client.on_connect = lambda c, u, f, rc, p=None: c.subscribe(INJECT_TOPIC)
        print(f"[Inject] Lab scenario injection ON (listening on {INJECT_TOPIC})")
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
    parser.add_argument("--allow-inject", action="store_true",
                        help="Let experiments/auto_record.py act out lab scenarios (lab use only)")
    args = parser.parse_args()
    if args.allow_inject and not args.mqtt_host:
        parser.error("--allow-inject needs --mqtt-host")

    init_db(args.db)
    if args.mqtt_host:
        connect_mqtt(args.mqtt_host, args.mqtt_port, args.allow_inject)
    if args.allow_inject:
        threading.Thread(target=door_actor, args=(args.db,), daemon=True).start()

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
