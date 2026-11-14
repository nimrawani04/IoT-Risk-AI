"""
Anomaly Detection Engine using Isolation Forest.
Trains on normal baseline IoT telemetry and evaluates incoming windows
with cross-layer behavioral metrics.
"""

import os
import argparse
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from features import load_sensor_telemetry, load_network_telemetry, extract_cross_layer_features
from risk import RiskAssessmentEngine

MODEL_PATH = "data/model.joblib"

ALL_FEATURE_COLUMNS = [
    # Device / Sensor Features
    "event_rate",
    "interval_mean",
    "interval_std",
    "mq135_raw_mean",
    "mq135_raw_std",
    "mq135_raw_unique",
    "mq135_raw_is_stuck",
    "distance_cm_mean",
    "distance_cm_std",
    "distance_cm_unique",
    "distance_cm_is_stuck",
    "motion_mean",
    "ir_count_mean",
    # Network Features
    "net_publish_rate",
    "net_replay_count",
    "net_unauthorized_count",
    "net_interval_mean_ms",
    "net_interval_std_ms"
]


def train(features_df=None, output_path=MODEL_PATH, contamination=0.05, min_samples=20):
    if features_df is None:
        df_sensor = load_sensor_telemetry()
        df_net = load_network_telemetry()
        features_df = extract_cross_layer_features(df_sensor, df_net)

    if len(features_df) < min_samples:
        raise ValueError(
            f"Insufficient data windows: found {len(features_df)}, need at least {min_samples}. "
            f"Run collector/simulation to accumulate normal baseline observations."
        )

    columns = [c for c in ALL_FEATURE_COLUMNS if c in features_df.columns]
    if not columns:
        raise ValueError("No matching feature columns found in dataset.")

    X = features_df[columns].replace([float("inf"), float("-inf")], float("nan"))

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", IsolationForest(
            n_estimators=120,
            contamination=contamination,
            random_state=42
        ))
    ])

    pipeline.fit(X)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    joblib.dump({
        "pipeline": pipeline,
        "columns": columns
    }, output_path)

    print(f"[Detector] Baseline Isolation Forest trained on {len(features_df)} windows.")
    print(f"[Detector] Feature columns ({len(columns)}): {columns}")
    print(f"[Detector] Saved model bundle to: {output_path}")
    return pipeline, columns


def predict(features_df=None, model_path=MODEL_PATH, output_csv="data/detections.csv"):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file {model_path} not found. Train first with 'python detector.py train'.")

    saved = joblib.load(model_path)
    pipeline = saved["pipeline"]
    columns = saved["columns"]

    if features_df is None:
        df_sensor = load_sensor_telemetry()
        df_net = load_network_telemetry()
        features_df = extract_cross_layer_features(df_sensor, df_net)

    if features_df.empty:
        print("[Detector] No feature data available for inference.")
        return pd.DataFrame()

    # Align columns
    for col in columns:
        if col not in features_df.columns:
            features_df[col] = 0.0

    X = features_df[columns].replace([float("inf"), float("-inf")], float("nan"))
    features_df["prediction"] = pipeline.predict(X)
    features_df["anomaly_score"] = pipeline.decision_function(X)
    features_df["status"] = features_df["prediction"].map({1: "Normal", -1: "Anomalous"})

    # Evaluate Risk per window
    risk_results = []
    for _, row in features_df.iterrows():
        is_stuck = bool(
            row.get("mq135_raw_is_stuck", 0) or row.get("distance_cm_is_stuck", 0)
        )
        assessment = RiskAssessmentEngine.assess(
            anomaly_detected=(row["prediction"] == -1),
            anomaly_score=row["anomaly_score"],
            event_rate=row.get("event_rate", 30.0),
            is_sensor_stuck=is_stuck,
            replay_count=int(row.get("net_replay_count", 0)),
            unauthorized_count=int(row.get("net_unauthorized_count", 0)),
            publish_rate=row.get("net_publish_rate", 0.0)
        )
        risk_results.append(assessment)

    features_df["risk_category"] = [r["category"] for r in risk_results]
    features_df["severity"] = [r["severity"] for r in risk_results]
    features_df["risk_score"] = [r["risk_score"] for r in risk_results]
    features_df["evidence_notes"] = ["; ".join(r["evidence"]) if r["evidence"] else "Normal operation" for r in risk_results]

    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    features_df.to_csv(output_csv, index=False)
    print(f"[Detector] Detection completed on {len(features_df)} windows. Saved to {output_csv}")
    return features_df


def main():
    parser = argparse.ArgumentParser(description="IoT Anomaly Detector")
    parser.add_argument("mode", choices=["train", "predict"], help="Operation mode")
    parser.add_argument("--model", default=MODEL_PATH, help="Path to model file")
    parser.add_argument("--out", default="data/detections.csv", help="Path for output detections CSV")
    args = parser.parse_args()

    if args.mode == "train":
        train(output_path=args.model)
    elif args.mode == "predict":
        df_res = predict(model_path=args.model, output_csv=args.out)
        if not df_res.empty:
            print(df_res[["received_at", "status", "risk_category", "risk_score", "evidence_notes"]].tail(15))


if __name__ == "__main__":
    main()
