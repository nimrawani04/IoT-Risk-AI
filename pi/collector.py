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
LCD_DEVICE = "arduino_2"  # the LCD sits next to the reader on the door node
DOOR_DEVICE = "arduino_2"
# A valid card is only accepted if the corridor ultrasonic saw someone this close in the
# last few seconds; otherwise the "scan" came from a cloned/relayed card or a faked message.
PRESENCE_CM = 120
PRESENCE_SEC = 5
ECHO_DEAD_SEC = 30  # no echo for this long = ultrasonic down (an open corridor gives brief no-echo gaps)
door_distances = []  # (time, distance_cm) of the door node's recent readings
last_echo_at = 0.0

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
    """{UID: name}. One card per line: the UID (hex, as printed by the door node), optionally
    followed by the holder's name, e.g. "613E7017 Milad". Lines starting with # are ignored."""
    cards = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split(maxsplit=1)
                if parts and not parts[0].startswith("#"):
                    cards[parts[0].upper()] = parts[1] if len(parts) > 1 else ""
    except FileNotFoundError:
        pass
    return cards


def show_on_lcd(line1, line2=""):
    port = ports_by_device.get(LCD_DEVICE)
    if port is None:
        print(f"[LCD] (door node not connected) {line1} | {line2}")
        return
    try:
        port.write(f"LCD:{line1[:16]}|{line2[:16]}\n".encode("ascii", errors="replace"))
    except Exception as e:
        print(f"[LCD] Write failed: {e}")


def note_door_distance(distance):
    global last_echo_at
    now = time.time()
    if distance is not None and distance >= 0:
        last_echo_at = now
    door_distances.append((now, distance))
    while door_distances and now - door_distances[0][0] > PRESENCE_SEC:
        door_distances.pop(0)


def person_at_door():
    """True / False, or None when the ultrasonic has given no echo at all for ECHO_DEAD_SEC (fault or unplugged).

    A few seconds of no echo is just an empty corridor (nothing within range), not a fault.
    """
    if time.time() - last_echo_at > ECHO_DEAD_SEC:
        return None
    recent = [d for t, d in door_distances if time.time() - t <= PRESENCE_SEC and d is not None and d >= 0]
    return bool(recent) and min(recent) <= PRESENCE_CM


def handle_rfid_scan(data, db_path=DB_PATH):
    uid = str(data.get("uid", "")).upper()
    cards = load_allowed_uids()
    name = cards.get(uid, "")
    reason = None
    if uid not in cards:
        reason = "unknown_card"
    else:
        present = person_at_door()
        # Fail closed: without proof someone is standing there, a valid card is not enough.
        if present is None:
            reason = "presence_sensor_unavailable"
        elif not present:
            reason = "no_person_detected"
    granted = reason is None
    event = "access_granted" if granted else "access_denied"
    device = data.get("device", "unknown")
    payload = {"device": device, "event": event, "uid": uid, "at": get_timestamp()}
    if name:
        payload["name"] = name
    if reason:
        payload["reason"] = reason
    # Timestamp keeps repeat scans of the same card from looking like MQTT replays.
    record(device, event, payload, db_path)
    lcd_line2 = {None: name or uid, "unknown_card": uid, "no_person_detected": "No one detected",
                 "presence_sensor_unavailable": "Door sensor down"}[reason]
    show_on_lcd("Access granted" if granted else "Access denied", lcd_line2)
    print(f"[Access] {uid} {name} -> {event}{f' ({reason})' if reason else ''}")


# --- Lab scenario injection (only with --allow-inject) ---------------------
# Lets experiments/auto_record.py act out faults and door scenarios remotely by
# changing real readings at the gateway, so nobody has to unplug wires or walk
# through the door. Off by default: anyone on the network could otherwise fake data.
INJECT_TOPIC = "lab/inject"
UNKNOWN_UID = "DEADBEEF"
inject = {"scenario": None, "until": 0.0, "plan": [], "crossings": [],
          "presence_until": 0.0, "room_motion_until": 0.0}


def _entry(scan, people=1):
    """Walk up, maybe scan, then `people` cross in one second apart, move around inside, and leave."""
    stay = random.uniform(15, 35)
    steps = [(0, "approach", 4 + people), (2, scan, None)] if scan else [(0, "approach", 3 + people)]
    t_in = 4 if scan else 3
    steps += [(t_in + i, "cross_in", None) for i in range(people)]
    steps += [(t_in + 1, "room_motion", stay)]
    steps += [(t_in + 1 + stay + i, "cross_out", None) for i in range(people)]
    return steps


# Each scenario: (plan of (delay s, step, arg), seconds until the next repeat)
DOOR_SCENARIOS = {
    "normal": (lambda: _entry("scan_valid"), (40, 70)),
    "normal_scan_no_entry": (lambda: [(0, "approach", 6), (2, "scan_valid", None)], (15, 30)),
    "attack_brute_force": (lambda: [(0, "approach", 4), (1.5, "scan_unknown", None)], (2, 4)),
    "attack_slow_brute_force": (lambda: [(0, "approach", 4), (1.5, "scan_unknown", None)], (6, 10)),
    "attack_tailgating": (lambda: _entry("scan_valid", people=3), (40, 60)),
    "attack_break_in": (lambda: _entry(None), (30, 45)),
    # Someone already inside (came through a window, hid earlier): room motion, no door activity.
    "attack_intruder_inside": (lambda: [(0, "room_motion", random.uniform(10, 30))], (20, 40)),
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
    inject.update(scenario=scenario, until=time.time() + seconds, plan=[], crossings=[],
                  presence_until=0.0, room_motion_until=0.0)
    print(f"[Inject] {scenario or 'cleared'} for {seconds:.0f}s")


def apply_fault(data):
    """Change a real sensor_reading to match the active scenario. Returns None to drop it.

    Layout: arduino_2 = door node (RFID, IR, corridor ultrasonic), arduino_1 = room node (PIR, gas).
    """
    s, device, now = active_scenario(), data.get("device"), time.time()
    if device == "arduino_2":
        if s and now < inject["presence_until"]:
            data["distance_cm"] = round(random.uniform(35, 75), 2)  # someone in the corridor at the door
        if s == "fault_ultrasonic":
            data["distance_cm"] = -1  # what the firmware sends when no echo comes back
        if s == "fault_rfid":
            data["rfid_ok"] = 0
        if inject["crossings"]:
            # One person per reading, like real people walking through one after another.
            direction = inject["crossings"].pop(0)
            data["ir_count"] = data.get("ir_count", 0) + 1
            data["ir"] = 1
            if direction == "out":
                # Leaving: seen in the corridor only AFTER crossing (this reading stays clear).
                inject["presence_until"] = max(inject["presence_until"], now + random.uniform(2, 4))
    elif device == "arduino_1":
        if s == "fault_node_offline":
            return None
        if s and now < inject["room_motion_until"]:
            data["motion"] = int(random.random() < 0.85)
        if s == "fault_gas_sensor":
            # shortcut: random values stand in for a floating A0 pin; record a real unplug to compare.
            data["mq135_raw"] = random.randint(0, 1023)
    return data


def door_actor(db_path=DB_PATH):
    """Acts out the active door/room scenario as timed steps (see DOOR_SCENARIOS)."""
    last, next_at, next_linger = None, 0.0, 0.0
    while True:
        s, now = active_scenario(), time.time()
        if s != last:
            last, next_at, next_linger = s, now + random.uniform(2, 5), now + random.uniform(10, 40)
        # shortcut: nobody lingers at the door while a visit is in progress, so exits stay
        # unambiguous; in real life someone waiting outside as another leaves looks like an entry.
        if s in LINGER_SCENARIOS and now >= next_linger and not inject["plan"]:
            inject["presence_until"] = max(inject["presence_until"], now + random.uniform(5, 30))
            next_linger = now + random.uniform(40, 90)
        if s in DOOR_SCENARIOS and now >= next_at:
            make_plan, gap = DOOR_SCENARIOS[s]
            inject["plan"] += [(now + delay, step, arg) for delay, step, arg in make_plan()]
            inject["plan"].sort(key=lambda x: x[0])
            next_at = now + random.uniform(*gap)
        while s and inject["plan"] and inject["plan"][0][0] <= now:
            _, step, arg = inject["plan"].pop(0)
            if step == "approach":
                inject["presence_until"] = max(inject["presence_until"], now + arg)
            elif step == "room_motion":
                inject["room_motion_until"] = max(inject["room_motion_until"], now + arg)
            elif step in ("cross_in", "cross_out"):
                inject["crossings"].append("in" if step == "cross_in" else "out")
            elif step in ("scan_valid", "scan_unknown"):
                uid = random.choice(sorted(load_allowed_uids()) or ["613E7017"]) if step == "scan_valid" else UNKNOWN_UID
                # Same line the door node prints (uptime_ms makes repeat scans of a card unique).
                handle_line(json.dumps({"device": "arduino_2", "event": "rfid_scan", "uid": uid,
                                        "uptime_ms": int(time.time() * 1000)}), "inject", db_path=db_path)
        time.sleep(0.25)


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
        if device == DOOR_DEVICE and "distance_cm" in data:
            note_door_distance(data["distance_cm"])

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
    distance_base = 190.0  # empty corridor; scenarios add people

    while True:
        uptime = int(time.time() * 1000)
        if device_name == "arduino_1":  # room node
            payload = {
                "device": "arduino_1",
                "event": "sensor_reading",
                "mq135_raw": int(max(50, min(1023, mq135_base + random.gauss(0, 4)))),
                "motion": 1 if random.random() < 0.02 else 0,  # an empty room: rare PIR noise
                "uptime_ms": uptime
            }
        else:  # door node
            ir_count = 0  # nobody crosses unless a scenario says so
            payload = {
                "device": "arduino_2",
                "event": "sensor_reading",
                "distance_cm": round(max(5.0, distance_base + random.gauss(0, 1.2)), 2),
                "ir": ir_count,
                "ir_count": ir_count,
                "rfid_ok": 1,
                "uptime_ms": uptime
            }

        # Same path as a real serial line: scenario changes, presence tracking, storage, MQTT.
        handle_line(json.dumps(payload), f"mock-{device_name}", db_path=db_path)
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
