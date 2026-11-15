"""
Research Evaluation & Hypothesis Testing Script.
Compares:
 1. Sensor-Only Model (Physical features only)
 2. Network-Only Model (MQTT network features only)
 3. Cross-Layer Combined Model (Our Proposed Behavioral Approach)

Evaluates Detection Metrics: Precision, Recall, F1-Score, False Positive Rate (FPR),
and Fault-vs-Attack Disambiguation Capability.
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Add parent directory to path to import pi modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pi")))

from features import load_sensor_telemetry, load_network_telemetry, extract_cross_layer_features
from risk import RiskAssessmentEngine

GROUND_TRUTH_PATH = "data/ground_truth.csv"
SUMMARY_OUTPUT = "data/evaluation_summary.csv"


SENSOR_ONLY_FEATURES = [
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
    "ir_count_mean"
]

NETWORK_ONLY_FEATURES = [
    "net_publish_rate",
    "net_replay_count",
    "net_unauthorized_count",
    "net_interval_mean_ms",
    "net_interval_std_ms"
]

COMBINED_FEATURES = SENSOR_ONLY_FEATURES + NETWORK_ONLY_FEATURES


def fit_and_evaluate(name, feature_subset, train_df, test_df):
    cols = [c for c in feature_subset if c in train_df.columns]

    X_train = train_df[cols].replace([float("inf"), float("-inf")], float("nan"))
    X_test = test_df[cols].replace([float("inf"), float("-inf")], float("nan"))

    pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", IsolationForest(n_estimators=120, contamination="auto", random_state=42))
    ])

    pipe.fit(X_train)
    test_scores = pipe.decision_function(X_test)
    # Decision score < 0.0 indicates isolation anomaly relative to normal tree depth
    binary_preds = np.where(test_scores < 0.0, 1, 0)
    y_true = test_df["is_anomaly"].values

    prec = precision_score(y_true, binary_preds, zero_division=0)
    rec = recall_score(y_true, binary_preds, zero_division=0)
    f1 = f1_score(y_true, binary_preds, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_true, binary_preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "Model": name,
        "Features Count": len(cols),
        "Precision": round(prec, 4),
        "Recall": round(rec, 4),
        "F1-Score": round(f1, 4),
        "FPR": round(fpr, 4),
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn)
    }, binary_preds


def evaluate_discrimination(test_df):
    """
    Evaluates whether evidence-based risk assessment accurately distinguishes
    physical sensor faults from security attack scenarios.
    """
    correct_classifications = 0
    total_evaluated = 0

    for _, row in test_df.iterrows():
        scenario = row.get("scenario", "")
        if scenario == "NORMAL":
            continue

        is_stuck = bool(row.get("mq135_raw_is_stuck", 0) or row.get("distance_cm_is_stuck", 0))
        assessment = RiskAssessmentEngine.assess(
            anomaly_detected=True,
            anomaly_score=-0.2,
            event_rate=row.get("event_rate", 30.0),
            is_sensor_stuck=is_stuck,
            replay_count=int(row.get("net_replay_count", 0)),
            unauthorized_count=int(row.get("net_unauthorized_count", 0)),
            publish_rate=row.get("net_publish_rate", 0.0)
        )

        expected_type = "FAULT" if "FAULT" in scenario else "ATTACK"
        assigned_type = "FAULT" if assessment["is_fault_indicator"] and not assessment["is_security_indicator"] else (
            "ATTACK" if assessment["is_security_indicator"] else "UNEXPLAINED"
        )

        if expected_type == assigned_type:
            correct_classifications += 1
        total_evaluated += 1

    acc = (correct_classifications / total_evaluated) if total_evaluated > 0 else 0.0
    return round(acc, 4), correct_classifications, total_evaluated


def main():
    print("=================================================================")
    print("  AI-BASED IoT BEHAVIOURAL RISK ASSESSMENT — RESEARCH BENCHMARK  ")
    print("=================================================================\n")

    # 1. Load Data
    df_sensor = load_sensor_telemetry()
    df_net = load_network_telemetry()

    if df_sensor.empty:
        print("[!] No telemetry database found. Generating synthetic dataset first...")
        from generate_test_data import generate_experiment_dataset
        generate_experiment_dataset(windows_per_scenario=30)
        df_sensor = load_sensor_telemetry()
        df_net = load_network_telemetry()

    features_df = extract_cross_layer_features(df_sensor, df_net)
    print(f"Loaded {len(features_df)} feature time windows.")

    if not os.path.exists(GROUND_TRUTH_PATH):
        print(f"[!] Ground truth file {GROUND_TRUTH_PATH} not found.")
        return

    gt_df = pd.read_csv(GROUND_TRUTH_PATH)

    # Align features with ground truth
    merged = features_df.copy()
    min_len = min(len(merged), len(gt_df))
    merged = merged.iloc[:min_len].copy()
    merged["is_anomaly"] = gt_df["is_anomaly"].iloc[:min_len].values
    merged["scenario"] = gt_df["scenario"].iloc[:min_len].values

    # 2. Split into Train (Normal only) and Test (All scenarios)
    train_normal = merged[merged["scenario"] == "NORMAL"].copy()
    test_all = merged.copy()

    print(f"Training set: {len(train_normal)} normal windows.")
    print(f"Evaluation test set: {len(test_all)} mixed scenarios windows.\n")

    # 3. Benchmark Models
    results = []
    r_sensor, _ = fit_and_evaluate("1. Sensor-Only Model", SENSOR_ONLY_FEATURES, train_normal, test_all)
    r_net, _ = fit_and_evaluate("2. Network-Only Model", NETWORK_ONLY_FEATURES, train_normal, test_all)
    r_comb, _ = fit_and_evaluate("3. Cross-Layer Proposed Model", COMBINED_FEATURES, train_normal, test_all)

    results.extend([r_sensor, r_net, r_comb])

    summary_df = pd.DataFrame(results)
    summary_df.to_csv(SUMMARY_OUTPUT, index=False)

    print("--- ANOMALY DETECTION BENCHMARK RESULTS ---")
    print(summary_df[["Model", "Precision", "Recall", "F1-Score", "FPR", "TP", "FP", "FN"]].to_string(index=False))

    # 4. Evaluate Discrimination Accuracy
    disc_acc, n_correct, n_total = evaluate_discrimination(test_all)
    print("\n--- FAULT vs ATTACK DISAMBIGUATION BENCHMARK ---")
    print(f"Fault vs. Attack Disambiguation Accuracy: {disc_acc * 100:.2f}% ({n_correct}/{n_total} correctly categorized)")
    print(f"Detailed results saved to: {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()
