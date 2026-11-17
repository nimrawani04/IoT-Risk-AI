"""
AI Detection Engine.

Two models, trained on the system's own recorded data:
  1. Isolation Forest (unsupervised): learns what normal windows look like and
     scores how unusual each new window is.
  2. Random Forest (supervised): trained on labelled sessions recorded with
     experiments/record_session.py; says WHICH scenario a window looks like
     (normal, a specific fault, or a specific attack) and how confident it is.
Each verdict comes with the features that drove it, and the rule-based risk
engine (risk.py) combines everything into one explainable assessment.

Modes:
  python pi/detector.py train      # fit both models from data/telemetry.db
  python pi/detector.py predict    # score all stored windows once
  python pi/detector.py live       # score each new window every few seconds
  python pi/detector.py live --reports   # + local LLM incident reports (Ollama)
"""

import os
import time
import sqlite3
import argparse
import threading

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from features import (DB_PATH, load_sensor_telemetry, load_network_telemetry,
                      load_access_events, extract_cross_layer_features)
from risk import RiskAssessmentEngine

MODEL_PATH = "data/model.joblib"
WINDOW = "10s"
WINDOW_SEC = 10

SENSOR_FEATURES = [
    "event_rate", "interval_mean", "interval_std",
    "mq135_raw_delta", "mq135_raw_std",
    "distance_cm_delta", "distance_cm_std", "distance_cm_missing",
    "motion_mean", "rfid_ok_mean",
]
NETWORK_FEATURES = [
    "net_publish_rate", "net_replay_count", "net_unauthorized_count",
    "net_interval_mean_ms", "net_interval_std_ms", "net_replay_count_1m",
]
DOOR_FEATURES = ["access_granted", "access_denied", "ir_passes", "unauthorized_passes",
                 "unused_grants", "access_denied_1m", "unauthorized_passes_1m",
                 "entries", "exits", "entries_unconfirmed_1m", "motion_while_empty", "motion_while_empty_1m"]
ALL_FEATURES = SENSOR_FEATURES + NETWORK_FEATURES + DOOR_FEATURES

FEATURE_LABELS = {
    "event_rate": "sensor messages", "interval_mean": "gap between readings",
    "interval_std": "timing jitter", "mq135_raw_mean": "gas level",
    "mq135_raw_delta": "gas change (vs last 10 min)", "distance_cm_delta": "door distance change (vs last 10 min)",
    "unused_grants": "card scans with nobody entering", "access_denied_1m": "denied scans (last minute)",
    "unauthorized_passes_1m": "crossings without a card (last minute)",
    "net_replay_count_1m": "replayed messages (last minute)",
    "entries": "people entering", "exits": "people leaving",
    "entries_unconfirmed_1m": "entries with no room motion after (last minute)",
    "motion_while_empty": "room motion while empty", "motion_while_empty_1m": "room motion while empty (last minute)", "mq135_raw_std": "gas variation",
    "distance_cm_mean": "door distance", "distance_cm_std": "distance variation",
    "distance_cm_missing": "missing ultrasonic echoes", "motion_mean": "motion",
    "rfid_ok_mean": "RFID reader health", "net_publish_rate": "MQTT messages",
    "net_replay_count": "replayed messages", "net_unauthorized_count": "unknown-device messages",
    "net_interval_mean_ms": "MQTT message gap", "net_interval_std_ms": "MQTT timing jitter",
    "access_granted": "granted scans", "access_denied": "denied scans",
    "ir_passes": "doorway crossings", "unauthorized_passes": "crossings without a card",
}

DETECTION_COLUMNS = [
    "window_start", "anomaly_score", "is_anomaly", "ml_scenario", "ml_category", "ml_confidence",
    "reasons", "risk_category", "severity", "risk_score", "evidence", "report",
]


def category_of(scenario):
    """'attack_replay' -> 'attack', 'fault_rfid' -> 'fault', 'normal' -> 'normal'."""
    return scenario if scenario == "normal" else str(scenario).split("_")[0]


def build_features(db_path=DB_PATH, since=None):
    return extract_cross_layer_features(
        load_sensor_telemetry(db_path, since),
        load_network_telemetry(db_path, since),
        WINDOW,
        load_access_events(db_path, since),
    )


def load_sessions(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        return pd.read_sql_query("SELECT * FROM sessions WHERE ended_at IS NOT NULL ORDER BY id", conn)
    except Exception:
        return pd.DataFrame()
    finally:
        conn.close()


DOOR_ATTACK_EVIDENCE = {
    "attack_brute_force": "access_denied_1m",
    "attack_slow_brute_force": "access_denied_1m",
    "attack_tailgating": "unauthorized_passes_1m",
    "attack_break_in": "unauthorized_passes_1m",
    "attack_spoofed_entry": "entries_unconfirmed_1m",
    "attack_intruder_inside": "motion_while_empty_1m",
}


def label_windows(feats, sessions):
    """Tag each window that lies fully inside a recorded session with that session's scenario."""
    feats = feats.copy()
    feats["scenario"] = None
    feats["session_id"] = -1
    start = feats["received_at"]
    end = start + pd.Timedelta(WINDOW)
    for s in sessions.itertuples():
        inside = ((start >= pd.to_datetime(s.started_at, utc=True, format="ISO8601"))
                  & (end <= pd.to_datetime(s.ended_at, utc=True, format="ISO8601")))
        feats.loc[inside, "scenario"] = s.scenario
        feats.loc[inside, "session_id"] = s.id
    # Door attacks happen every few seconds, so many windows in those sessions show nothing.
    # Labelling those quiet windows 'attack' teaches the model that quiet = attack; leave them unlabelled.
    for scenario, evidence in DOOR_ATTACK_EVIDENCE.items():
        quiet = (feats["scenario"] == scenario) & (feats.reindex(columns=[evidence], fill_value=0)[evidence] <= 0)
        feats.loc[quiet, ["scenario", "session_id"]] = [None, -1]
    feats["category"] = feats["scenario"].map(lambda s: category_of(s) if s else None)
    return feats


def feature_matrix(df, columns=ALL_FEATURES):
    return df.reindex(columns=columns, fill_value=0.0).astype(float)


def train(db_path=DB_PATH, output_path=MODEL_PATH, min_windows=30):
    feats = build_features(db_path)
    if feats.empty:
        raise ValueError("No telemetry yet. Run the collector (Pi) and mqtt_monitor (laptop) first.")

    labelled = label_windows(feats, load_sessions(db_path))
    normal = labelled[labelled["category"] == "normal"]
    if len(normal) < min_windows:
        # shortcut: unlabelled data may contain incidents; record a 'normal' session for a clean baseline.
        print(f"[Detector] Only {len(normal)} windows in recorded 'normal' sessions; "
              "training the anomaly model on all unlabelled data instead.")
        normal = labelled[labelled["category"].isna() | (labelled["category"] == "normal")]
    if len(normal) < min_windows:
        raise ValueError(f"Need at least {min_windows} windows ({min_windows * WINDOW_SEC}s) of normal data, "
                         f"found {len(normal)}.")

    X_normal = feature_matrix(normal)
    # contamination sets the alarm threshold: ~2% of normal windows will score below 0.
    anomaly_model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42).fit(X_normal)

    classifier = None
    sessions_used = labelled[labelled["scenario"].notna()]
    counts = sessions_used["scenario"].value_counts()
    usable = counts[counts >= 5].index
    sessions_used = sessions_used[sessions_used["scenario"].isin(usable)]
    if sessions_used["category"].nunique() >= 2:
        classifier = RandomForestClassifier(
            n_estimators=300, class_weight="balanced", min_samples_leaf=2, random_state=42,
        ).fit(feature_matrix(sessions_used), sessions_used["scenario"])
        print(f"[Detector] Classifier trained on {len(sessions_used)} labelled windows: "
              f"{dict(sessions_used['scenario'].value_counts())}")
    else:
        print("[Detector] No classifier yet: record a 'normal' session plus at least one fault or "
              "attack session (experiments/record_session.py), then train again.")

    std = X_normal.std().fillna(0.0)
    bundle = {
        "anomaly_model": anomaly_model,
        "classifier": classifier,
        "features": ALL_FEATURES,
        "baseline_mean": X_normal.mean(),
        # Floor so a feature that never moved in normal data (e.g. replays = 0) still ranks
        # as the reason when it suddenly does.
        "baseline_std": np.maximum(std, np.maximum(0.1 * X_normal.mean().abs(), 0.5)),
        "window": WINDOW,
    }
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    joblib.dump(bundle, output_path)
    print(f"[Detector] Anomaly model trained on {len(X_normal)} normal windows. Saved to {output_path}")
    return bundle


def explain(X, bundle, top=3):
    """Top features that are furthest from normal, weighted by how much the classifier relies on them."""
    z = (X - bundle["baseline_mean"]) / bundle["baseline_std"]
    weights = (pd.Series(bundle["classifier"].feature_importances_, index=X.columns) + 0.05
               if bundle["classifier"] is not None else 1.0)
    reasons = []
    for i in range(len(X)):
        row_z = z.iloc[i]
        ranked = (row_z.abs() * weights).sort_values(ascending=False)
        parts = []
        for col in ranked.index[:top]:
            if abs(row_z[col]) < 3:
                break
            direction = "high" if row_z[col] > 0 else "low"
            parts.append(f"{FEATURE_LABELS.get(col, col)} {direction} "
                         f"({X.iloc[i][col]:.4g} vs normal {bundle['baseline_mean'][col]:.4g})")
        reasons.append("; ".join(parts))
    return reasons


def score(feats, bundle):
    X = feature_matrix(feats, bundle["features"])
    anomaly_scores = bundle["anomaly_model"].decision_function(X)

    if bundle["classifier"] is not None:
        proba = bundle["classifier"].predict_proba(X)
        scenarios = bundle["classifier"].classes_[proba.argmax(axis=1)]
        confidences = proba.max(axis=1)
    else:
        scenarios = [None] * len(X)
        confidences = np.zeros(len(X))

    reasons = explain(X, bundle)
    rows = []
    for i, (_, f) in enumerate(feats.iterrows()):
        ml_category = category_of(scenarios[i]) if scenarios[i] else None
        risk = RiskAssessmentEngine.assess(
            anomaly_detected=anomaly_scores[i] < 0,
            anomaly_score=anomaly_scores[i],
            event_rate=f.get("event_rate", 0.0),
            is_sensor_stuck=bool(f.get("distance_cm_is_stuck", 0)),
            replay_count=int(f.get("net_replay_count", 0)),
            unauthorized_count=int(f.get("net_unauthorized_count", 0)),
            publish_rate=f.get("net_publish_rate", 0.0),
            window_sec=WINDOW_SEC,
            access_denied=int(f.get("access_denied", 0)),
            unauthorized_passes=int(f.get("unauthorized_passes", 0)),
            reader_down="rfid_ok_mean" in feats.columns and f.get("rfid_ok_mean", 1) < 0.5,
            sensor_missing=f.get("distance_cm_missing_30s", f.get("distance_cm_missing", 0)) >= 0.8,
            card_no_person=int(f.get("card_no_person", 0)),
            unused_grants=int(f.get("unused_grants", 0)),
            access_denied_1m=int(f.get("access_denied_1m", 0)),
            entries_unconfirmed=int(f.get("entries_unconfirmed", 0)),
            motion_while_empty=int(f.get("motion_while_empty", 0)),
            ml_category=ml_category,
            ml_confidence=float(confidences[i]),
        )
        rows.append({
            "window_start": f["received_at"].isoformat(),
            "anomaly_score": float(anomaly_scores[i]),
            "is_anomaly": int(anomaly_scores[i] < 0),
            "ml_scenario": scenarios[i],
            "ml_category": ml_category,
            "ml_confidence": float(confidences[i]),
            "reasons": reasons[i],
            "risk_category": risk["category"],
            "severity": risk["severity"],
            "risk_score": int(risk["risk_score"]),
            "evidence": "; ".join(risk["evidence"]) or "Normal operation",
            "report": None,
        })
    return pd.DataFrame(rows, columns=DETECTION_COLUMNS)


def init_detections(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            window_start TEXT PRIMARY KEY, anomaly_score REAL, is_anomaly INTEGER,
            ml_scenario TEXT, ml_category TEXT, ml_confidence REAL, reasons TEXT,
            risk_category TEXT, severity TEXT, risk_score INTEGER, evidence TEXT, report TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_detections(results, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.executemany(
        f"INSERT OR REPLACE INTO detections ({', '.join(DETECTION_COLUMNS)}) "
        f"VALUES ({', '.join('?' * len(DETECTION_COLUMNS))})",
        [tuple(None if pd.isna(v) else v for v in row) for row in results.itertuples(index=False)],
    )
    conn.commit()
    conn.close()


def load_bundle(model_path=MODEL_PATH):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"{model_path} not found. Train first: python pi/detector.py train")
    return joblib.load(model_path)


def predict(db_path=DB_PATH, model_path=MODEL_PATH):
    bundle = load_bundle(model_path)
    feats = build_features(db_path)
    if feats.empty:
        print("[Detector] No feature data available.")
        return pd.DataFrame()
    results = score(feats, bundle)
    init_detections(db_path)
    save_detections(results, db_path)
    print(f"[Detector] Scored {len(results)} windows into the detections table.")
    return results


REPORT_SEVERITIES = {"HIGH", "CRITICAL"}
REPORT_COOLDOWN_SEC = 120


def _write_report(detection, db_path):
    from incident_report import generate_report  # only needed with --reports
    text = generate_report(detection)
    if text:
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE detections SET report = ? WHERE window_start = ?", (text, detection["window_start"]))
        conn.commit()
        conn.close()
        print(f"[Report] {detection['window_start']}\n{text}\n")


def live(db_path=DB_PATH, model_path=MODEL_PATH, interval=2.0, reports=False):
    bundle = load_bundle(model_path)
    init_detections(db_path)
    window = pd.Timedelta(WINDOW)
    # Wait for late MQTT messages, and for the readings after a crossing that tell entering from leaving.
    grace = pd.Timedelta(seconds=6)
    last_scored = pd.Timestamp.now(tz="UTC") - window * 3
    last_report = {}
    print(f"[Live] Scoring {WINDOW} windows every {interval}s. Reports: {'on' if reports else 'off'}. Ctrl+C to stop.")

    while True:
        now = pd.Timestamp.now(tz="UTC")
        since = now - pd.Timedelta(minutes=12)  # 10 min baseline for the *_delta features
        feats = build_features(db_path, since=since.isoformat())
        if not feats.empty:
            done = feats[(feats["received_at"] + window + grace <= now)
                         & (feats["received_at"] > last_scored)
                         & (feats["received_at"] >= since + window)]  # first window may be cut off
            if not done.empty:
                results = score(done, bundle)
                save_detections(results, db_path)
                last_scored = done["received_at"].max()
                for r in results.to_dict("records"):
                    ml = f" | AI: {r['ml_scenario']} {r['ml_confidence']:.0%}" if r["ml_scenario"] else ""
                    print(f"[Live] {r['window_start'][11:19]} {r['risk_category']:<30} "
                          f"risk {r['risk_score']:>3} anomaly {r['anomaly_score']:+.3f}{ml}")
                    if reports and r["severity"] in REPORT_SEVERITIES:
                        last = last_report.get(r["risk_category"], 0)
                        if time.time() - last > REPORT_COOLDOWN_SEC:
                            last_report[r["risk_category"]] = time.time()
                            threading.Thread(target=_write_report, args=(r, db_path), daemon=True).start()
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="IoT AI detector")
    parser.add_argument("mode", choices=["train", "predict", "live"])
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--model", default=MODEL_PATH)
    parser.add_argument("--interval", type=float, default=2.0, help="live mode: seconds between checks")
    parser.add_argument("--reports", action="store_true", help="live mode: write incident reports with Ollama")
    args = parser.parse_args()

    if args.mode == "train":
        train(args.db, args.model)
    elif args.mode == "predict":
        res = predict(args.db, args.model)
        if not res.empty:
            print(res[["window_start", "risk_category", "risk_score", "ml_scenario", "reasons"]].tail(15).to_string(index=False))
    else:
        try:
            live(args.db, args.model, args.interval, args.reports)
        except KeyboardInterrupt:
            print("\n[Live] Stopped.")


if __name__ == "__main__":
    main()
