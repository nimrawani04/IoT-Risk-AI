"""
Controlled Test Data Generator for IoT Behavioural Experiments.
Simulates Ground-Truth Scenarios:
 - Scenario A: Normal Operation (Baseline)
 - Scenario B: Device / Sensor Malfunctions (Stuck reading, connection drops)
 - Scenario C1: Message Flooding / DoS
 - Scenario C2: Replay Attack (Duplicate payload injection)
 - Scenario C3: Unauthorized / Rogue Node Spoofing
"""

import os
import json
import time
import random
import hashlib
import sqlite3
import argparse
from datetime import datetime, timezone, timedelta

DB_PATH = "data/telemetry.db"
GROUND_TRUTH_CSV = "data/ground_truth.csv"


def get_timestamp(offset_sec=0):
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_sec)
    return dt.isoformat()


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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS network_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            topic TEXT NOT NULL,
            client_id TEXT,
            payload TEXT NOT NULL,
            payload_hash TEXT,
            is_replay INTEGER DEFAULT 0,
            is_unauthorized INTEGER DEFAULT 0,
            msg_interval_ms REAL
        )
    """)
    conn.commit()
    conn.close()


def generate_experiment_dataset(db_path=DB_PATH, windows_per_scenario=20, window_sec=30):
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    # Clear existing data for clean reproducible experiment
    conn.execute("DELETE FROM telemetry")
    conn.execute("DELETE FROM network_telemetry")
    conn.commit()

    labels_log = []
    current_time_offset = 0

    scenarios = [
        ("NORMAL", windows_per_scenario),
        ("SENSOR_FAULT_STUCK", windows_per_scenario),
        ("SENSOR_FAULT_DROPOUT", windows_per_scenario),
        ("ATTACK_FLOODING", windows_per_scenario),
        ("ATTACK_REPLAY", windows_per_scenario),
        ("ATTACK_ROGUE_DEVICE", windows_per_scenario),
    ]

    print(f"[ExpGen] Starting generation of {len(scenarios)} controlled scenarios...")

    for scenario_name, num_windows in scenarios:
        print(f"[ExpGen] Generating Scenario: {scenario_name} ({num_windows} windows x {window_sec}s)...")

        for w in range(num_windows):
            window_start_ts = get_timestamp(current_time_offset)
            is_anomaly = 0 if scenario_name == "NORMAL" else 1
            anomaly_type = "BENIGN" if scenario_name == "NORMAL" else ("FAULT" if "FAULT" in scenario_name else "ATTACK")

            labels_log.append({
                "window_start": window_start_ts,
                "scenario": scenario_name,
                "is_anomaly": is_anomaly,
                "anomaly_type": anomaly_type
            })

            # Generate messages inside this window
            step = 1.0  # 1 message per second baseline
            sec_elapsed = 0.0

            # Variables for fault states
            stuck_mq4 = 230
            replay_payload_cache = None

            while sec_elapsed < window_sec:
                t_offset = current_time_offset + sec_elapsed
                ts_iso = get_timestamp(t_offset)

                # 1. Physical Node 1 (PIR & Button)
                if scenario_name == "NORMAL" or "FAULT" in scenario_name or "REPLAY" in scenario_name or "ROGUE" in scenario_name:
                    mot = 1 if random.random() < 0.1 else 0
                    btn = 1 if random.random() < 0.03 else 0
                    p1 = {"device": "arduino_1", "event": "sensor_reading", "motion": mot, "button": btn, "uptime_ms": int(t_offset * 1000)}
                    conn.execute("INSERT INTO telemetry (received_at, device, event, payload) VALUES (?, ?, ?, ?)",
                                 (ts_iso, "arduino_1", "sensor_reading", json.dumps(p1)))

                # 2. Physical Node 2 (MQ4 & Distance)
                if scenario_name == "NORMAL":
                    mq4 = int(220 + random.gauss(0, 3))
                    dist = round(45.0 + random.gauss(0, 1.0), 2)
                    p2 = {"device": "arduino_2", "event": "sensor_reading", "mq4_raw": mq4, "distance_cm": dist, "uptime_ms": int(t_offset * 1000)}
                    conn.execute("INSERT INTO telemetry (received_at, device, event, payload) VALUES (?, ?, ?, ?)",
                                 (ts_iso, "arduino_2", "sensor_reading", json.dumps(p2)))

                elif scenario_name == "SENSOR_FAULT_STUCK":
                    # Stuck constant reading with 0 variance
                    p2 = {"device": "arduino_2", "event": "sensor_reading", "mq4_raw": stuck_mq4, "distance_cm": 45.0, "uptime_ms": int(t_offset * 1000)}
                    conn.execute("INSERT INTO telemetry (received_at, device, event, payload) VALUES (?, ?, ?, ?)",
                                 (ts_iso, "arduino_2", "sensor_reading", json.dumps(p2)))

                elif scenario_name == "SENSOR_FAULT_DROPOUT":
                    # Connection drops / missing distance timeouts
                    if random.random() > 0.4:
                        p2 = {"device": "arduino_2", "event": "sensor_reading", "mq4_raw": int(220 + random.gauss(0, 3)), "distance_cm": -1.0, "uptime_ms": int(t_offset * 1000)}
                        conn.execute("INSERT INTO telemetry (received_at, device, event, payload) VALUES (?, ?, ?, ?)",
                                     (ts_iso, "arduino_2", "sensor_reading", json.dumps(p2)))

                elif scenario_name == "ATTACK_FLOODING":
                    # Flooding with high rate (10 msgs/sec)
                    for f in range(8):
                        sub_iso = get_timestamp(t_offset + f * 0.1)
                        p_flood = {"device": "arduino_2", "event": "sensor_reading", "mq4_raw": 999, "distance_cm": 1.0, "uptime_ms": int(t_offset * 1000)}
                        conn.execute("INSERT INTO telemetry (received_at, device, event, payload) VALUES (?, ?, ?, ?)",
                                     (sub_iso, "arduino_2", "sensor_reading", json.dumps(p_flood)))
                        # Network flood
                        conn.execute("INSERT INTO network_telemetry (received_at, topic, client_id, payload, payload_hash, is_replay, is_unauthorized, msg_interval_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                     (sub_iso, "iot/sensors/env", "arduino_2", json.dumps(p_flood), "hash_flood", 0, 0, 100.0))

                # 3. MQTT Network Events
                if scenario_name == "NORMAL" or "FAULT" in scenario_name:
                    net_p = {"device": "arduino_2", "status": "ok", "nonce": random.randint(10000, 99999)}
                    net_str = json.dumps(net_p)
                    h = hashlib.sha256(net_str.encode()).hexdigest()
                    conn.execute("INSERT INTO network_telemetry (received_at, topic, client_id, payload, payload_hash, is_replay, is_unauthorized, msg_interval_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                 (ts_iso, "iot/sensors/env", "arduino_2", net_str, h, 0, 0, 1000.0))

                elif scenario_name == "ATTACK_REPLAY":
                    if replay_payload_cache is None:
                        replay_payload_cache = json.dumps({"device": "arduino_1", "command": "unlock_door", "token": "AUTH_TOKEN_SEC_99"})
                    h = hashlib.sha256(replay_payload_cache.encode()).hexdigest()
                    conn.execute("INSERT INTO network_telemetry (received_at, topic, client_id, payload, payload_hash, is_replay, is_unauthorized, msg_interval_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                 (ts_iso, "iot/access/control", "arduino_1", replay_payload_cache, h, 1, 0, 1000.0))

                elif scenario_name == "ATTACK_ROGUE_DEVICE":
                    rogue_p = json.dumps({"device": "rogue_esp32_injector", "cmd": "inject_false_gas_alert", "val": 950})
                    h = hashlib.sha256(rogue_p.encode()).hexdigest()
                    conn.execute("INSERT INTO network_telemetry (received_at, topic, client_id, payload, payload_hash, is_replay, is_unauthorized, msg_interval_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                 (ts_iso, "iot/override/commands", "rogue_esp32_injector", rogue_p, h, 0, 1, 1000.0))

                sec_elapsed += step

            current_time_offset += window_sec

    conn.commit()
    conn.close()

    # Save Ground Truth
    import pandas as pd
    gt_df = pd.DataFrame(labels_log)
    gt_df.to_csv(GROUND_TRUTH_CSV, index=False)
    print(f"[ExpGen] Successfully generated {len(gt_df)} experimental windows stored in SQLite and {GROUND_TRUTH_CSV}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Experiment Data Generator")
    parser.add_argument("--windows", type=int, default=25, help="Number of 30s windows per scenario")
    parser.add_argument("--db", default=DB_PATH, help="Database path")
    args = parser.parse_args()

    generate_experiment_dataset(db_path=args.db, windows_per_scenario=args.windows)
