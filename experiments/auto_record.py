"""
Record every training scenario automatically, no hands needed.

Needs the Pi collector started with --allow-inject (it fakes the faults and door
activity on real readings), and mqtt_monitor.py running on this laptop.
Network attacks (replay / flood / rogue) are run from here with attacks.py.

  python experiments/auto_record.py                 # everything, 2 repeats (~70 min)
  python experiments/auto_record.py --repeats 1     # quick pass (~35 min)
  python experiments/auto_record.py --only attack_tailgating normal_scan_no_entry

Then: python pi/detector.py train
"""

import json
import time
import sqlite3
import argparse
import threading

import attacks
from record_session import record, DB_PATH, SCENARIOS

NETWORK_ATTACKS = {"attack_replay": attacks.replay, "attack_flood": attacks.flood, "attack_rogue": attacks.rogue,
                   "attack_spoofed_entry": attacks.spoof_entry}
SETTLE_SEC = 20  # unrecorded gap so one scenario doesn't bleed into the next window
# The room must have been quiet for 3+ minutes to count as empty (features.EMPTY_RESET_SEC).
NEEDS_EMPTY_ROOM = {"attack_intruder_inside": 190}


def telemetry_count(db_path):
    try:
        with sqlite3.connect(db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
    except sqlite3.Error:
        return 0


def run(scenario, minutes, broker, port, db_path, control):
    seconds = int(minutes * 60)
    attack_thread = None
    if scenario in NETWORK_ATTACKS:
        client = attacks.connect(broker, port, f"lab_attack_{scenario}")
        attack_thread = threading.Thread(target=NETWORK_ATTACKS[scenario], args=(client, seconds), daemon=True)
        attack_thread.start()
    else:
        control.publish("lab/inject", json.dumps({"scenario": scenario, "seconds": seconds + 5}))
    try:
        record(scenario, minutes, db_path, notes="auto_record",
               how="Nothing. It's acted out automatically, so don't touch the hardware.")
    finally:
        control.publish("lab/inject", json.dumps({"scenario": None, "seconds": 0}))
        if attack_thread:
            attack_thread.join(timeout=10)
            client.loop_stop()
            client.disconnect()


def main():
    parser = argparse.ArgumentParser(description="Record all scenarios automatically")
    parser.add_argument("--broker", default=attacks.DEFAULT_BROKER)
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--minutes", type=float, default=2.0, help="length of each fault/attack session")
    parser.add_argument("--normal-minutes", type=float, default=8.0)
    parser.add_argument("--only", nargs="+", choices=list(SCENARIOS), help="record just these scenarios")
    args = parser.parse_args()

    before = telemetry_count(args.db)
    time.sleep(5)
    if telemetry_count(args.db) == before:
        raise SystemExit(f"No new readings in {args.db} in 5 s. Start mqtt_monitor.py (and the Pi collector) first.")

    control = attacks.connect(args.broker, args.port, "lab_auto_record")
    plan = list(args.only or SCENARIOS)
    total = sum(args.normal_minutes if s == "normal" else args.minutes for s in plan)
    print(f"Plan: {len(plan)} scenarios x {args.repeats} = about {total * args.repeats + len(plan) * args.repeats * SETTLE_SEC / 60:.0f} min")
    print("Reminder: the Pi collector must run with --allow-inject, or faults and door scenarios record as normal.\n")
    try:
        for rep in range(args.repeats):
            for scenario in plan:
                print(f"\n=== Round {rep + 1}/{args.repeats}: {scenario} ===")
                if scenario in NEEDS_EMPTY_ROOM:
                    print(f"Waiting {NEEDS_EMPTY_ROOM[scenario]}s so the room counts as empty...")
                    time.sleep(NEEDS_EMPTY_ROOM[scenario])
                run(scenario, args.normal_minutes if scenario == "normal" else args.minutes,
                    args.broker, args.port, args.db, control)
                time.sleep(SETTLE_SEC)
    except KeyboardInterrupt:
        print("\nStopped. Sessions finished so far are saved.")
    finally:
        control.publish("lab/inject", json.dumps({"scenario": None, "seconds": 0}))
        control.loop_stop()
        control.disconnect()
    print("\nDone. Next: python pi/detector.py train")


if __name__ == "__main__":
    main()
