"""
Feature Extraction for Cross-Layer IoT Behavioral Analysis.
Extracts device-level sensor statistics and network-level communication features
over configured time windows (e.g., 30s).
"""

import json
import sqlite3
import pandas as pd
import numpy as np

DB_PATH = "data/telemetry.db"


def load_sensor_telemetry(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("""
            SELECT received_at, device, payload
            FROM telemetry
            WHERE event = 'sensor_reading'
            ORDER BY id
        """).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()

    records = []
    for received_at, device, payload in rows:
        try:
            data = json.loads(payload)
            data["received_at"] = received_at
            data["device"] = device
            records.append(data)
        except Exception:
            continue

    return pd.DataFrame(records)


def load_network_telemetry(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query("""
            SELECT received_at, topic, client_id, is_replay, is_unauthorized, msg_interval_ms
            FROM network_telemetry
            ORDER BY id
        """, conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()

    return df


def extract_sensor_features(df_sensor, window="30s"):
    if df_sensor.empty:
        return pd.DataFrame()

    df = df_sensor.copy()
    df["received_at"] = pd.to_datetime(df["received_at"], utc=True)
    df = df.set_index("received_at")

    feature_frames = []
    sensor_cols = ["mq4_raw", "distance_cm", "motion", "button"]

    for device, group in df.groupby("device"):
        group = group.sort_index()
        resampled = group.resample(window)

        feats = pd.DataFrame(index=resampled.size().index)
        feats["event_rate"] = resampled.size()

        # Compute inter-message arrival standard deviation
        intervals = group.index.to_series().diff().dt.total_seconds()
        feats["interval_mean"] = intervals.resample(window).mean().fillna(1.0)
        feats["interval_std"] = intervals.resample(window).std().fillna(0.0)

        for col in sensor_cols:
            if col in group.columns:
                feats[f"{col}_mean"] = group[col].resample(window).mean().fillna(0.0)
                feats[f"{col}_std"] = group[col].resample(window).std().fillna(0.0)
                feats[f"{col}_unique"] = group[col].resample(window).nunique().fillna(0)
                # Check for stuck reading (more than 10 events in window but std == 0)
                feats[f"{col}_is_stuck"] = (
                    (feats["event_rate"] >= 10) & (feats[f"{col}_std"] < 1e-5)
                ).astype(int)
            else:
                feats[f"{col}_mean"] = 0.0
                feats[f"{col}_std"] = 0.0
                feats[f"{col}_unique"] = 0
                feats[f"{col}_is_stuck"] = 0

        feats["device"] = device
        feature_frames.append(feats)

    if not feature_frames:
        return pd.DataFrame()

    # Merge all device feature frames on received_at
    combined_sensor = None
    for f in feature_frames:
        f_clean = f.drop(columns=["device"], errors="ignore")
        if combined_sensor is None:
            combined_sensor = f_clean
        else:
            # Combine columns, summing event rates and taking max of metrics
            combined_sensor = combined_sensor.combine_first(f_clean)
            if "event_rate" in f_clean.columns and "event_rate" in combined_sensor.columns:
                combined_sensor["event_rate"] = combined_sensor["event_rate"] + f_clean["event_rate"]

    return combined_sensor.reset_index()


def extract_network_features(df_network, window="30s"):
    if df_network.empty:
        return pd.DataFrame()

    df = df_network.copy()
    df["received_at"] = pd.to_datetime(df["received_at"], utc=True)
    df = df.set_index("received_at")

    resampled = df.resample(window)
    feats = pd.DataFrame(index=resampled.size().index)

    feats["net_publish_rate"] = resampled.size()
    feats["net_replay_count"] = df["is_replay"].resample(window).sum()
    feats["net_unauthorized_count"] = df["is_unauthorized"].resample(window).sum()
    feats["net_interval_mean_ms"] = df["msg_interval_ms"].resample(window).mean().fillna(0.0)
    feats["net_interval_std_ms"] = df["msg_interval_ms"].resample(window).std().fillna(0.0)

    return feats.reset_index()


def extract_cross_layer_features(df_sensor, df_network, window="30s"):
    sensor_feats = extract_sensor_features(df_sensor, window=window)
    net_feats = extract_network_features(df_network, window=window)

    if sensor_feats.empty and net_feats.empty:
        return pd.DataFrame()

    if net_feats.empty:
        # Fill network columns with zero baselines
        sensor_feats["net_publish_rate"] = 0
        sensor_feats["net_replay_count"] = 0
        sensor_feats["net_unauthorized_count"] = 0
        sensor_feats["net_interval_mean_ms"] = 0.0
        sensor_feats["net_interval_std_ms"] = 0.0
        return sensor_feats

    if sensor_feats.empty:
        return net_feats

    # Merge on window timestamp
    combined = pd.merge(sensor_feats, net_feats, on="received_at", how="left")
    combined["net_publish_rate"] = combined["net_publish_rate"].fillna(0)
    combined["net_replay_count"] = combined["net_replay_count"].fillna(0)
    combined["net_unauthorized_count"] = combined["net_unauthorized_count"].fillna(0)
    combined["net_interval_mean_ms"] = combined["net_interval_mean_ms"].fillna(0.0)
    combined["net_interval_std_ms"] = combined["net_interval_std_ms"].fillna(0.0)

    return combined


if __name__ == "__main__":
    df_s = load_sensor_telemetry()
    df_n = load_network_telemetry()
    feats = extract_cross_layer_features(df_s, df_n)
    print(f"Extracted {len(feats)} feature windows.")
    if not feats.empty:
        print(feats.tail(10))
        feats.to_csv("data/features.csv", index=False)
        print("Saved to data/features.csv")
