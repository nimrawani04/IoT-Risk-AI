"""
Record a labelled session for training and evaluating the AI.

Run it on the laptop (where mqtt_monitor.py writes data/telemetry.db) while you
perform the scenario. It only stores the scenario name and start/end times; the
readings themselves are already being saved by mqtt_monitor.py.

  python experiments/record_session.py --list
  python experiments/record_session.py normal --minutes 10
  python experiments/record_session.py attack_brute_force --minutes 2

Press Ctrl+C to end a session early; it is still saved.
"""

import time
import sqlite3
import argparse
from datetime import datetime, timezone

DB_PATH = "data/telemetry.db"

# Scenario names start with normal / fault_ / attack_ (normal_* also counts as normal); the AI learns the scenario
# and reports the category in front of the underscore.
SCENARIOS = {
    "normal": "Use the room normally: scan a valid card and walk through, move around, leave sensors alone.",
    "normal_scan_no_entry": "Scan a valid card but don't walk through (changed your mind).",
    "fault_ultrasonic": "Unplug the HC-SR04 Echo wire (D4) on Arduino 1, or cover the sensor completely.",
    "fault_rfid": "Unplug the RC522's 3.3V wire on Arduino 2.",
    "fault_gas_sensor": "Unplug the MQ-135 AO wire (A0) on Arduino 1.",
    "fault_node_offline": "Unplug Arduino 1's USB cable from the Pi.",
    "attack_brute_force": "Scan the unregistered card over and over.",
    "attack_slow_brute_force": "Scan the unregistered card about every 8 seconds (too slow for a 10 s window).",
    "attack_tailgating": "Scan a valid card once, then pass through the IR beam two or three times.",
    "attack_break_in": "Pass through the IR beam without scanning any card.",
    "attack_replay": "In another terminal: python experiments/attacks.py replay",
    "attack_flood": "In another terminal: python experiments/attacks.py flood",
    "attack_rogue": "In another terminal: python experiments/attacks.py rogue",
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def init_sessions(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            notes TEXT
        )
    """)


def record(scenario, minutes, db_path=DB_PATH, notes="", how=None):
    conn = sqlite3.connect(db_path)
    init_sessions(conn)
    cur = conn.execute("INSERT INTO sessions (scenario, started_at, notes) VALUES (?, ?, ?)",
                       (scenario, now_iso(), notes))
    conn.commit()
    session_id = cur.lastrowid

    print(f"Recording session {session_id}: {scenario}")
    print(f"What to do: {how or SCENARIOS.get(scenario, 'custom scenario')}")
    end = time.time() + minutes * 60
    try:
        while time.time() < end:
            print(f"\r  {int(end - time.time()):4d}s left (Ctrl+C to stop early)", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Stopped early.")
    conn.execute("UPDATE sessions SET ended_at = ? WHERE id = ?", (now_iso(), session_id))
    conn.commit()
    conn.close()
    print(f"\nSaved session {session_id} ({scenario}). Put things back to normal before the next one.")


def main():
    parser = argparse.ArgumentParser(description="Record a labelled scenario session")
    parser.add_argument("scenario", nargs="?", help="scenario name, see --list")
    parser.add_argument("--minutes", type=float, default=3.0)
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--notes", default="")
    parser.add_argument("--list", action="store_true", help="show the scenarios and recorded sessions")
    args = parser.parse_args()

    if args.list or not args.scenario:
        print("Scenarios:")
        for name, how in SCENARIOS.items():
            print(f"  {name:<20} {how}")
        conn = sqlite3.connect(args.db)
        init_sessions(conn)
        rows = conn.execute("SELECT scenario, COUNT(*), "
                            "SUM((julianday(ended_at) - julianday(started_at)) * 1440) "
                            "FROM sessions WHERE ended_at IS NOT NULL GROUP BY scenario").fetchall()
        conn.close()
        print("\nRecorded so far:" if rows else "\nNo sessions recorded yet.")
        for scenario, n, mins in rows:
            print(f"  {scenario:<20} {n} session(s), {mins:.1f} min")
        return

    if not (args.scenario == "normal" or args.scenario.startswith(("normal_", "fault_", "attack_"))):
        parser.error("scenario names must be 'normal' or start with 'normal_', 'fault_' or 'attack_'")
    record(args.scenario, args.minutes, args.db, args.notes)


if __name__ == "__main__":
    main()
