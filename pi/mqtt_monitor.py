"""
MQTT Network Monitor and Security Evidence Collector.
Subscribes to IoT topics, tracks packet timing, message replay signatures,
topic flooding, and unauthorized publisher identities.
"""

import os
import json
import time
import hashlib
import sqlite3
import argparse
import threading
from datetime import datetime, timezone
from collections import defaultdict, deque

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

DB_PATH = "data/telemetry.db"
DEFAULT_BROKER = "localhost"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "iot/#"

AUTHORIZED_DEVICES = {"arduino_1", "arduino_2", "heltec_node_1", "gateway_pi"}


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path=DB_PATH):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
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


class NetworkAnalyzer:
    def __init__(self, db_path=DB_PATH, replay_window_sec=60.0):
        self.db_path = db_path
        self.replay_window_sec = replay_window_sec
        # Store (hash, timestamp)
        self.seen_hashes = deque()
        # Last message time per topic/client
        self.last_seen_time = {}

    def analyze_and_log(self, topic, client_id, payload_str):
        now_ts = time.time()
        received_iso = get_timestamp()

        # 1. Check unauthorized client
        is_unauthorized = 1 if (client_id and client_id not in AUTHORIZED_DEVICES) else 0

        # 2. Replay detection via payload hashing
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        cutoff = now_ts - self.replay_window_sec
        while self.seen_hashes and self.seen_hashes[0][1] < cutoff:
            self.seen_hashes.popleft()

        is_replay = 0
        for h, t in self.seen_hashes:
            if h == payload_hash:
                is_replay = 1
                break

        self.seen_hashes.append((payload_hash, now_ts))

        # 3. Inter-arrival time interval
        key = (topic, client_id)
        if key in self.last_seen_time:
            interval_ms = (now_ts - self.last_seen_time[key]) * 1000.0
        else:
            interval_ms = None
        self.last_seen_time[key] = now_ts

        # Store in DB
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO network_telemetry 
            (received_at, topic, client_id, payload, payload_hash, is_replay, is_unauthorized, msg_interval_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            received_iso,
            topic,
            client_id,
            payload_str,
            payload_hash,
            is_replay,
            is_unauthorized,
            interval_ms
        ))
        conn.commit()
        conn.close()

        return {
            "received_at": received_iso,
            "topic": topic,
            "client_id": client_id,
            "is_replay": bool(is_replay),
            "is_unauthorized": bool(is_unauthorized),
            "interval_ms": interval_ms
        }


def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[MQTT] Connected successfully to broker.")
        client.subscribe(userdata["topic"])
        print(f"[MQTT] Subscribed to topic '{userdata['topic']}'")
    else:
        print(f"[MQTT] Failed to connect, return code {rc}")


def on_message(client, userdata, msg):
    try:
        payload_str = msg.payload.decode("utf-8", errors="ignore")
        client_id = None
        try:
            data = json.loads(payload_str)
            client_id = data.get("device") or data.get("client_id")
        except Exception:
            pass

        analyzer = userdata["analyzer"]
        res = analyzer.analyze_and_log(msg.topic, client_id, payload_str)
        print(f"[MQTT-NET] {res['received_at']} Topic={msg.topic} Client={client_id} Replay={res['is_replay']} Rogue={res['is_unauthorized']}")
    except Exception as e:
        print(f"[MQTT] Error processing message: {e}")


def run_subscriber(broker=DEFAULT_BROKER, port=DEFAULT_PORT, topic=DEFAULT_TOPIC, db_path=DB_PATH):
    if mqtt is None:
        print("Error: paho-mqtt is not installed. Run 'pip install paho-mqtt'")
        return

    init_db(db_path)
    analyzer = NetworkAnalyzer(db_path)
    client = mqtt.Client(userdata={"topic": topic, "analyzer": analyzer})
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"[MQTT] Connecting to {broker}:{port}...")
    try:
        client.connect(broker, port, 60)
        client.loop_forever()
    except Exception as e:
        print(f"[MQTT] Broker connection error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Network Security Monitor")
    parser.add_argument("--broker", default=DEFAULT_BROKER, help="MQTT broker address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="MQTT broker port")
    parser.add_argument("--topic", default=DEFAULT_TOPIC, help="MQTT subscription topic")
    parser.add_argument("--db", default=DB_PATH, help="Database path")
    args = parser.parse_args()

    run_subscriber(args.broker, args.port, args.topic, args.db)
