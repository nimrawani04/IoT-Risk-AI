"""
Evidence-Based Risk Assessment Engine.
Combines machine-learning anomaly detections with deterministic physical
and network-layer evidence to produce interpretable, actionable risk evaluations.
"""

from typing import Dict, Any, List


class RiskAssessmentEngine:
    """
    Evaluates telemetry features and anomaly predictions to classify the nature
    of an IoT anomaly (Sensor Fault vs Security Attack vs Benign Noise).
    """

    @staticmethod
    def assess(
        anomaly_detected: bool,
        anomaly_score: float = 0.0,
        event_rate: float = 30.0,
        is_sensor_stuck: bool = False,
        replay_count: int = 0,
        unauthorized_count: int = 0,
        publish_rate: float = 0.0,
        interval_anomaly: bool = False
    ) -> Dict[str, Any]:
        """
        Assesses operational and security risk based on observable evidence.

        Returns:
            Dict containing category, risk_score (0-100), severity, and evidence list.
        """
        evidence: List[str] = []
        is_security_indicator = False
        is_fault_indicator = False

        # 1. Device / Sensor Fault Evidence
        if is_sensor_stuck:
            evidence.append("Sensor reading stuck with zero variance (Hardware / ADC Fault)")
            is_fault_indicator = True

        if event_rate < 10.0:
            evidence.append(f"Abnormally low serial event rate ({event_rate:.1f} msgs/window) - potential connection drop")
            is_fault_indicator = True

        # 2. Network & Security Attack Evidence
        if replay_count > 0:
            evidence.append(f"Observed {replay_count} identical replayed payload signatures (Replay Attack Scenario)")
            is_security_indicator = True

        if unauthorized_count > 0:
            evidence.append(f"Observed {unauthorized_count} messages from unauthorized/unrecognized client IDs (Spoofing / Rogue Node)")
            is_security_indicator = True

        if publish_rate > 90.0 or event_rate > 90.0:
            evidence.append(f"Excessive message rate detected (Flood / DoS pattern: {max(publish_rate, event_rate):.1f} msgs/window)")
            is_security_indicator = True

        if interval_anomaly:
            evidence.append("Irregular inter-message timing jitter")

        # 3. Decision Logic & Severity Scoring
        if unauthorized_count > 0 and (replay_count > 0 or publish_rate > 90.0):
            category = "CRITICAL_ATTACK"
            severity = "CRITICAL"
            base_score = 90
        elif is_security_indicator:
            category = "SUSPICIOUS_SECURITY_BEHAVIOUR"
            severity = "HIGH"
            base_score = 75
        elif is_fault_indicator:
            category = "DEVICE_HARDWARE_FAULT"
            severity = "MEDIUM"
            base_score = 50
        elif anomaly_detected:
            category = "UNEXPLAINED_ANOMALY"
            severity = "LOW"
            base_score = 35
            evidence.append("Statistical deviation flagged by Isolation Forest without specific rule match")
        else:
            category = "NORMAL_OPERATION"
            severity = "NONE"
            base_score = 5

        # Score adjustment using raw ML decision score (decision_function is negative for anomalies)
        if anomaly_score < 0:
            deviation_penalty = min(20, int(abs(anomaly_score) * 40))
            risk_score = min(100, base_score + deviation_penalty)
        else:
            risk_score = max(0, min(100, base_score))

        return {
            "category": category,
            "severity": severity,
            "risk_score": risk_score,
            "evidence": evidence,
            "anomaly_detected": bool(anomaly_detected),
            "is_security_indicator": is_security_indicator,
            "is_fault_indicator": is_fault_indicator
        }


def assess_risk(anomaly_detected, replay_evidence=False, unauthorized_source=False, sensor_fault=False):
    """Legacy helper wrapper for backwards compatibility."""
    return RiskAssessmentEngine.assess(
        anomaly_detected=anomaly_detected,
        replay_count=1 if replay_evidence else 0,
        unauthorized_count=1 if unauthorized_source else 0,
        is_sensor_stuck=sensor_fault
    )


if __name__ == "__main__":
    # Test cases
    print("Test 1 - Normal:", RiskAssessmentEngine.assess(False, anomaly_score=0.15))
    print("Test 2 - Sensor Fault:", RiskAssessmentEngine.assess(True, anomaly_score=-0.12, is_sensor_stuck=True))
    print("Test 3 - Replay Attack:", RiskAssessmentEngine.assess(True, anomaly_score=-0.25, replay_count=4))
    print("Test 4 - Rogue Spoofing:", RiskAssessmentEngine.assess(True, anomaly_score=-0.35, unauthorized_count=3, publish_rate=120))
