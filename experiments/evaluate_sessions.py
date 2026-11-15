"""
Evaluate the AI on real, labelled sessions (recorded with record_session.py).

Answers the research questions with real hardware data:
  RQ1: does combining sensor + network + door features beat any single layer?
  RQ2: can the classifier tell normal / fault / attack apart?

Cross-validation splits by SESSION, so every test window comes from a recording
the models never saw during training (windows from the same session are too
similar to count as independent tests).

  python experiments/evaluate_sessions.py
"""

import os
import sys
import argparse

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix, classification_report

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pi")))
from detector import (DB_PATH, build_features, load_sessions, label_windows, feature_matrix,
                      SENSOR_FEATURES, NETWORK_FEATURES, DOOR_FEATURES, ALL_FEATURES)

SUBSETS = {
    "Sensor-only": SENSOR_FEATURES,
    "Network-only": NETWORK_FEATURES,
    "Door-only": DOOR_FEATURES,
    "Cross-layer (all)": ALL_FEATURES,
}
OUTPUT = "data/evaluation_sessions.csv"


def evaluate(db_path=DB_PATH):
    feats = build_features(db_path)
    if feats.empty:
        print("No telemetry found.")
        return None
    lab = label_windows(feats, load_sessions(db_path))
    lab = lab[lab["scenario"].notna()].reset_index(drop=True)
    if lab.empty:
        print("No labelled sessions yet. Record some with experiments/record_session.py.")
        return None

    y = lab["category"]
    groups = lab["session_id"]
    sessions_per_category = lab.groupby("category")["session_id"].nunique()
    print("Sessions per category:", sessions_per_category.to_dict())
    print("Windows per scenario:", lab["scenario"].value_counts().to_dict(), "\n")
    if y.nunique() < 2 or sessions_per_category.min() < 2 or "normal" not in sessions_per_category:
        print("Need at least 2 sessions each of 'normal' and of faults/attacks to cross-validate.")
        return None
    # Stratify by scenario so each test fold holds one repeat of every scenario: the model is
    # tested on a new recording of a fault/attack it knows, never on a type it has never seen.
    repeats = lab.groupby("scenario")["session_id"].nunique().min()
    if repeats < 2:
        print("Need at least 2 recorded sessions of every scenario.")
        return None
    cv = StratifiedGroupKFold(n_splits=int(min(5, repeats)), shuffle=True, random_state=42)

    # Second test closer to real use: train on older recordings, test on the newest one of each scenario.
    newest = lab["session_id"] == lab.groupby("scenario")["session_id"].transform("max")

    results, cross_layer_preds = [], None
    for name, cols in SUBSETS.items():
        X = feature_matrix(lab, cols)
        pred = pd.Series(index=lab.index, dtype=object)
        flagged = pd.Series(False, index=lab.index)
        for train_idx, test_idx in cv.split(X, lab["scenario"], groups):
            clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                         min_samples_leaf=2, random_state=42)
            clf.fit(X.iloc[train_idx], y.iloc[train_idx])
            pred.iloc[test_idx] = clf.predict(X.iloc[test_idx])

            normal_train = X.iloc[train_idx][y.iloc[train_idx] == "normal"]
            iso = IsolationForest(n_estimators=200, contamination=0.02, random_state=42).fit(normal_train)
            flagged.iloc[test_idx] = iso.decision_function(X.iloc[test_idx]) < 0

        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                     min_samples_leaf=2, random_state=42).fit(X[~newest], y[~newest])
        newest_f1 = f1_score(y[newest], clf.predict(X[newest]), average="macro")

        is_incident = y != "normal"
        tn, fp, fn, tp = confusion_matrix(is_incident, flagged, labels=[False, True]).ravel()
        results.append({
            "Features": name,
            "Classifier macro-F1 (normal/fault/attack)": round(f1_score(y, pred, average="macro"), 3),
            "Macro-F1, newest recordings": round(newest_f1, 3),
            "Anomaly precision": round(precision_score(is_incident, flagged, zero_division=0), 3),
            "Anomaly recall": round(recall_score(is_incident, flagged, zero_division=0), 3),
            "Anomaly FPR": round(fp / (fp + tn), 3) if (fp + tn) else 0.0,
        })
        if name == "Cross-layer (all)":
            cross_layer_preds = pred

    summary = pd.DataFrame(results)
    print(summary.to_string(index=False))
    print("\nCross-layer classifier, per category:")
    print(classification_report(y, cross_layer_preds, zero_division=0))
    labels = sorted(y.unique())
    print("Confusion matrix (rows = true, columns = predicted):")
    print(pd.DataFrame(confusion_matrix(y, cross_layer_preds, labels=labels), index=labels, columns=labels))

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    summary.to_csv(OUTPUT, index=False)
    print(f"\nSaved to {OUTPUT}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate the AI on recorded sessions")
    parser.add_argument("--db", default=DB_PATH)
    evaluate(parser.parse_args().db)
