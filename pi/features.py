"""
Feature Extraction for Cross-Layer IoT Behavioral Analysis.
Turns raw readings into one row per time window with three feature groups:
physical sensors, MQTT network behaviour, and door/access events.
"""

import json
import sqlite3
import pandas as pd
import numpy as np

DB_PATH = "data/telemetry.db"

# Numeric fields the Arduinos send. Each belongs to one board.
SENSOR_COLS = ["mq135_raw", "distance_cm", "motion", "ir_count", "rfid_ok"]
NET_COLS = ["net_publish_rate", "net_replay_count", "net_unauthorized_count",
            "net_interval_mean_ms", "net_interval_std_ms"]
DOOR_COLS = ["access_granted", "access_denied", "ir_passes", "unauthorized_passes"]


def _since_clause(since):
    return ("WHERE received_at >= ?", (since,)) if since else ("", ())


def load_sensor_telemetry(db_path=DB_PATH, since=None):
    where, args = _since_clause(since)
    where = f"{where} AND event = 'sensor_reading'" if where else "WHERE event = 'sensor_reading'"
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f"SELECT received_at, device, payload FROM telemetry {where} ORDER BY id", args).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()

    records = []
    for received_at, device, payload in rows:
        try:
            data = json.loads(payload)
        except ValueError:
            continue
        if isinstance(data, dict):
            data["received_at"] = received_at
            data["device"] = device
            records.append(data)

    return pd.DataFrame(records)


def load_network_telemetry(db_path=DB_PATH, since=None):
    where, args = _since_clause(since)
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(f"""
            SELECT received_at, topic, client_id, is_replay, is_unauthorized, msg_interval_ms
            FROM network_telemetry {where} ORDER BY id
        """, conn, params=args)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df


def load_access_events(db_path=DB_PATH, since=None):
    where, args = _since_clause(since)
    where = f"{where} AND" if where else "WHERE"
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(f"""
            SELECT received_at, event FROM telemetry
            {where} event IN ('access_granted', 'access_denied') ORDER BY id
        """, conn, params=args)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df


def extract_sensor_features(df_sensor, window="30s"):
    if df_sensor.empty:
        return pd.DataFrame()

    df = df_sensor.copy()
    df["received_at"] = pd.to_datetime(df["received_at"], utc=True, format="ISO8601")
    df = df.set_index("received_at")

    frames = []
    for device, group in df.groupby("device"):
        group = group.sort_index()
        feats = pd.DataFrame(index=group.resample(window).size().index)
        feats["event_rate"] = group.resample(window).size()

        intervals = group.index.to_series().diff().dt.total_seconds()
        feats["interval_mean"] = intervals.resample(window).mean()
        feats["interval_std"] = intervals.resample(window).std()

        # Only this board's own fields: placeholders here would hide the other board's values.
        for col in SENSOR_COLS:
            if col not in group.columns:
                continue
            values = pd.to_numeric(group[col], errors="coerce")
            if col == "distance_cm":
                # -1 means "no echo"; keep it out of the stats and count it as missing instead.
                feats["distance_cm_missing"] = (values < 0).resample(window).mean()
                values = values.where(values >= 0)
            r = values.resample(window)
            feats[f"{col}_mean"] = r.mean()
            feats[f"{col}_std"] = r.std()
            feats[f"{col}_unique"] = r.nunique()
            feats[f"{col}_is_stuck"] = ((r.count() >= 5) & (r.std() < 1e-5)).astype(int)
            if col == "ir_count":
                # shortcut: at most 1 crossing per 1 s reading. Hides IR flicker (10+ edges/s seen
                # with the old firmware) but undercounts two people in the same second.
                feats["ir_passes"] = values.clip(upper=1).resample(window).sum()
        frames.append(feats)

    wide = pd.concat(frames, axis=1)
    # Each sensor column comes from one board, so max() just picks the board that has it;
    # for shared timing columns it keeps the worst (largest) gap.
    combined = wide.T.groupby(level=0).max().T
    combined["event_rate"] = wide.loc[:, wide.columns == "event_rate"].sum(axis=1)
    combined.index.name = "received_at"
    return combined.fillna(0.0).reset_index()


def extract_network_features(df_network, window="30s"):
    if df_network.empty:
        return pd.DataFrame()

    df = df_network.copy()
    df["received_at"] = pd.to_datetime(df["received_at"], utc=True, format="ISO8601")
    df = df.set_index("received_at")

    feats = pd.DataFrame(index=df.resample(window).size().index)
    feats["net_publish_rate"] = df.resample(window).size()
    feats["net_replay_count"] = df["is_replay"].resample(window).sum()
    feats["net_unauthorized_count"] = df["is_unauthorized"].resample(window).sum()
    feats["net_interval_mean_ms"] = df["msg_interval_ms"].resample(window).mean()
    feats["net_interval_std_ms"] = df["msg_interval_ms"].resample(window).std()
    feats.index.name = "received_at"
    return feats.fillna(0.0).reset_index()


def extract_door_features(df_access, window="30s"):
    if df_access is None or df_access.empty:
        return pd.DataFrame()

    df = df_access.copy()
    df["received_at"] = pd.to_datetime(df["received_at"], utc=True, format="ISO8601")
    df = df.set_index("received_at")
    feats = pd.DataFrame(index=df.resample(window).size().index)
    feats["access_granted"] = (df["event"] == "access_granted").resample(window).sum()
    feats["access_denied"] = (df["event"] == "access_denied").resample(window).sum()
    feats.index.name = "received_at"
    return feats.reset_index()


def extract_cross_layer_features(df_sensor, df_network, window="30s", df_access=None):
    parts = [p for p in (extract_sensor_features(df_sensor, window),
                         extract_network_features(df_network, window),
                         extract_door_features(df_access, window)) if not p.empty]
    if not parts:
        return pd.DataFrame()

    combined = parts[0]
    for p in parts[1:]:
        combined = pd.merge(combined, p, on="received_at", how="outer")
    combined = combined.sort_values("received_at").reset_index(drop=True)

    for col in NET_COLS + DOOR_COLS:
        if col not in combined.columns:
            combined[col] = 0.0
    combined = combined.fillna(0.0)

    # People crossing the doorway beyond the cards granted just before (this or the previous
    # window, since a scan and the walk-through can straddle a window boundary).
    recent_grants = combined["access_granted"] + combined["access_granted"].shift(1, fill_value=0)
    combined["unauthorized_passes"] = (combined["ir_passes"] - recent_grants).clip(lower=0)
    # Cards granted in the previous window with nobody crossing then or since: scanned but no one
    # entered. Judged one window late so a walk-through just after the boundary still counts.
    prev = combined[["access_granted", "ir_passes"]].shift(1, fill_value=0)
    combined["unused_grants"] = (prev["access_granted"] - prev["ir_passes"] - combined["ir_passes"]).clip(lower=0)

    t = combined.set_index("received_at")
    # Change from the last 10 minutes instead of the raw level: the MQ-135 drifts by tens of
    # counts over hours, and the doorway distance depends on who is around. Sudden change matters.
    for col in ("mq135_raw_mean", "distance_cm_mean"):
        if col in t:
            baseline = t[col].rolling("10min", min_periods=6).median().shift(1)
            combined[col.replace("_mean", "_delta")] = (t[col] - baseline).fillna(0.0).to_numpy()
    # Last-minute totals catch attacks too slow to show up in one 10 s window.
    for col in ("access_denied", "unauthorized_passes", "net_replay_count"):
        combined[f"{col}_1m"] = t[col].rolling("60s").sum().to_numpy()
    return combined


if __name__ == "__main__":
    df_s = load_sensor_telemetry()
    df_n = load_network_telemetry()
    feats = extract_cross_layer_features(df_s, df_n, df_access=load_access_events())
    print(f"Extracted {len(feats)} feature windows.")
    if not feats.empty:
        print(feats.tail(10))
        feats.to_csv("data/features.csv", index=False)
        print("Saved to data/features.csv")
