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
DOOR_COLS = ["access_granted", "access_denied", "card_no_person", "ir_passes", "unauthorized_passes",
             "entries", "exits", "entries_unconfirmed", "motion_while_empty"]

# Door / room logic. PRESENCE_CM must match the collector's access check.
PRESENCE_CM = 120        # someone this close to the corridor ultrasonic is "at the door"
DIRECTION_SEC = 4        # look this far before/after an IR crossing to tell entering from leaving
CONFIRM_SEC = 30         # an entry should be followed by room motion within this time...
CONFIRM_MOTION = 3       # ...at least this many seconds of it (one blip can be PIR noise)
EMPTY_RESET_SEC = 180    # no crossings and only PIR noise this long -> assume the room is empty
PIR_NOISE = 0.05 * EMPTY_RESET_SEC  # motion seconds (5% of the time) that still count as an empty room


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
            SELECT received_at, event, json_extract(payload, '$.reason') AS reason FROM telemetry
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
    # A valid card scanned while the corridor ultrasonic saw nobody: cloned/relayed card, or someone dodging the sensor.
    reason = df["reason"] if "reason" in df else pd.Series("", index=df.index)
    feats["card_no_person"] = (reason == "no_person_detected").resample(window).sum()
    feats.index.name = "received_at"
    return feats.reset_index()


def _numeric_rows(df, *cols):
    if df.empty or not all(c in df.columns for c in cols):
        return pd.DataFrame(columns=["t", *cols])
    out = pd.DataFrame({"t": pd.to_datetime(df["received_at"], utc=True, format="ISO8601")})
    for c in cols:
        out[c] = pd.to_numeric(df[c], errors="coerce")
    return out.dropna().sort_values("t")


def extract_occupancy_features(df_sensor, window="30s"):
    """Entering vs leaving, room occupancy and the room-motion cross-checks.

    The corridor ultrasonic sees the outside of the door: someone near it just BEFORE the IR
    beam breaks is coming in; nobody before but someone near just AFTER is going out.
    """
    door = _numeric_rows(df_sensor, "distance_cm", "ir_count")
    room = _numeric_rows(df_sensor, "motion")
    if door.empty:
        return pd.DataFrame()
    epoch = pd.Timestamp(0, tz="UTC")
    sec = lambda ts: (ts - epoch).dt.total_seconds().to_numpy()  # unit-safe (pandas may store us or ns)
    near_t = sec(door.loc[(door.distance_cm >= 0) & (door.distance_cm <= PRESENCE_CM), "t"])
    cross = door[door.ir_count > 0]
    cross_t = sec(cross["t"])
    before = np.searchsorted(near_t, cross_t, side="left") - np.searchsorted(near_t, cross_t - DIRECTION_SEC, side="left")
    after = np.searchsorted(near_t, cross_t + DIRECTION_SEC, side="right") - np.searchsorted(near_t, cross_t, side="right")
    # Unknown direction counts as an entry: missing a break-in is worse than a false alarm.
    is_exit = (before == 0) & (after > 0)

    motion_t = sec(room.loc[room.motion > 0, "t"]) if not room.empty else np.array([])
    last_t = max(sec(door["t"]).max(), sec(room["t"]).max() if not room.empty else 0)
    rows = []  # (time, column) events, counted per window below
    for t, ex in zip(cross_t, is_exit):
        rows.append((t, "exits" if ex else "entries"))
        if not ex and t + CONFIRM_SEC <= last_t:
            confirmed = np.count_nonzero((motion_t > t) & (motion_t <= t + CONFIRM_SEC)) >= CONFIRM_MOTION
            if not confirmed:
                # Reported once the 30 s are up, so live mode can say it without seeing the future.
                rows.append((t + CONFIRM_SEC, "entries_unconfirmed"))

    # Occupancy: entries minus exits, walked through in time order with the room motion.
    # shortcut: starts at 0 at the beginning of the data; a missed exit (or a spoofed entry) is
    # only corrected once the room has been quiet - no crossings, PIR noise only - for 3 minutes.
    timeline = sorted([(t, "exit" if ex else "entry") for t, ex in zip(cross_t, is_exit)] +
                      [(t, "motion") for t in motion_t])
    occupancy, last_crossing, last_entry = 0, -1e18, -1e18
    for t, kind in timeline:
        recent_motion = np.searchsorted(motion_t, t, "left") - np.searchsorted(motion_t, t - EMPTY_RESET_SEC, "right")
        if t - last_crossing > EMPTY_RESET_SEC and recent_motion <= PIR_NOISE:
            occupancy = 0
        if kind == "entry":
            occupancy += 1
            last_entry = last_crossing = t
        elif kind == "exit":
            occupancy = max(occupancy - 1, 0)
            last_crossing = t
        elif occupancy == 0 and t - last_entry > CONFIRM_SEC:
            rows.append((t, "motion_while_empty"))

    cols = ["entries", "exits", "entries_unconfirmed", "motion_while_empty"]
    ev = pd.DataFrame(rows, columns=["t", "col"])
    ev["t"] = pd.to_datetime(ev["t"], unit="s", utc=True)
    idx = door.set_index("t").resample(window).size().index
    out = pd.DataFrame(0.0, index=idx, columns=cols)
    if not ev.empty:
        counts = ev.assign(n=1).pivot_table(index=pd.Grouper(key="t", freq=window), columns="col",
                                            values="n", aggfunc="sum")
        out = out.add(counts.reindex(columns=cols), fill_value=0).fillna(0.0)
    out.index.name = "received_at"
    return out.reset_index()


def extract_cross_layer_features(df_sensor, df_network, window="30s", df_access=None):
    parts = [p for p in (extract_sensor_features(df_sensor, window),
                         extract_network_features(df_network, window),
                         extract_door_features(df_access, window),
                         extract_occupancy_features(df_sensor, window)) if not p.empty]
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
    # People leaving don't need a card, so only entries count.
    combined["unauthorized_passes"] = (combined["entries"] - recent_grants).clip(lower=0)
    # Cards granted in the previous window with nobody crossing then or since: scanned but no one
    # entered. Judged one window late so a walk-through just after the boundary still counts.
    prev = combined[["access_granted", "entries"]].shift(1, fill_value=0)
    combined["unused_grants"] = (prev["access_granted"] - prev["entries"] - combined["entries"]).clip(lower=0)

    t = combined.set_index("received_at")
    # Change from the last 10 minutes instead of the raw level: the MQ-135 drifts by tens of
    # counts over hours, and the doorway distance depends on who is around. Sudden change matters.
    for col in ("mq135_raw_mean", "distance_cm_mean"):
        if col in t:
            baseline = t[col].rolling("10min", min_periods=6).median().shift(1)
            combined[col.replace("_mean", "_delta")] = (t[col] - baseline).fillna(0.0).to_numpy()
    # Last-minute totals catch attacks too slow to show up in one 10 s window.
    for col in ("access_denied", "unauthorized_passes", "net_replay_count",
                "entries_unconfirmed", "motion_while_empty"):
        combined[f"{col}_1m"] = t[col].rolling("60s").sum().to_numpy()
    # An empty corridor gives short no-echo gaps; a dead ultrasonic gives no echo for 30 s straight.
    if "distance_cm_missing" in t:
        combined["distance_cm_missing_30s"] = t["distance_cm_missing"].rolling("30s").min().to_numpy()
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
