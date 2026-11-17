"""
Evidence-Based Risk Assessment Engine.
Combines the AI models' output (anomaly score + fault/attack classifier) with
deterministic physical, network and door evidence to produce interpretable,
actionable risk evaluations.
"""

from typing import Dict, Any, List, Optional

# Normal traffic is two boards at 1 msg/s each.
FLOOD_MSGS_PER_SEC = 3.0
LOW_RATE_MSGS_PER_SEC = 1.5
BRUTE_FORCE_DENIALS = 3
SLOW_BRUTE_FORCE_DENIALS = 4  # per minute
EMPTY_ROOM_MOTION = 3  # seconds of motion in a 10 s window while nobody should be inside


class RiskAssessmentEngine:
    """
    Classifies a window as normal, a device fault or a security attack, with the
    evidence behind it.
    """

    @staticmethod
    def assess(
        anomaly_detected: bool,
        anomaly_score: float = 0.0,
        event_rate: float = 60.0,
        is_sensor_stuck: bool = False,
        replay_count: int = 0,
        unauthorized_count: int = 0,
        publish_rate: float = 0.0,
        interval_anomaly: bool = False,
        window_sec: float = 30.0,
        access_denied: int = 0,
        unauthorized_passes: int = 0,
        reader_down: bool = False,
        sensor_missing: bool = False,
        unused_grants: int = 0,
        access_denied_1m: int = 0,
        entries_unconfirmed: int = 0,
        motion_while_empty: int = 0,
        card_no_person: int = 0,
        ml_category: Optional[str] = None,
        ml_confidence: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Returns a dict with category, risk_score (0-100), severity and the evidence list.
        """
        evidence: List[str] = []
        is_security_indicator = False
        is_fault_indicator = False
        msg_rate = event_rate / window_sec
        pub_rate = publish_rate / window_sec

        # 1. Device / sensor fault evidence
        if is_sensor_stuck:
            evidence.append("Sensor reading stuck with zero variance (hardware / ADC fault)")
            is_fault_indicator = True
        if sensor_missing:
            evidence.append("Ultrasonic sensor returning no echo (disconnected or blocked)")
            is_fault_indicator = True
        if reader_down:
            evidence.append("RFID reader not responding (loose wiring, power, or tampering)")
            is_fault_indicator = True
        if msg_rate < LOW_RATE_MSGS_PER_SEC:
            evidence.append(f"Low sensor message rate ({msg_rate:.1f} msg/s) - a node may be offline")
            is_fault_indicator = True

        # 2. Network and door security evidence
        if replay_count > 0:
            evidence.append(f"{replay_count} replayed (identical) MQTT payloads")
            is_security_indicator = True
        if unauthorized_count > 0:
            evidence.append(f"{unauthorized_count} messages from unknown client IDs (rogue node)")
            is_security_indicator = True
        if pub_rate > FLOOD_MSGS_PER_SEC or msg_rate > FLOOD_MSGS_PER_SEC * 2:
            evidence.append(f"Excessive message rate ({max(pub_rate, msg_rate):.1f} msg/s) - flood / DoS pattern")
            is_security_indicator = True
        if access_denied >= BRUTE_FORCE_DENIALS:
            evidence.append(f"{access_denied} denied card scans - possible card brute-force")
            is_security_indicator = True
        elif access_denied_1m >= SLOW_BRUTE_FORCE_DENIALS:
            evidence.append(f"{access_denied_1m} denied card scans in the last minute - slow card brute-force")
            is_security_indicator = True
        elif access_denied > 0:
            evidence.append(f"{access_denied} denied card scan(s)")
        if card_no_person > 0:
            evidence.append(f"{int(card_no_person)} valid card scan(s) with nobody at the door - "
                            "cloned/relayed card, or someone avoiding the presence sensor")
            is_security_indicator = True
        if unauthorized_passes > 0:
            evidence.append(f"{int(unauthorized_passes)} doorway crossing(s) without a valid card (tailgating / break-in)")
            is_security_indicator = True
        if entries_unconfirmed > 0:
            evidence.append(f"{int(entries_unconfirmed)} entr(y/ies) through the door with no movement in the room "
                            "within 30 s - spoofed door data, or the room PIR has failed")
            is_security_indicator = True
        if motion_while_empty >= EMPTY_ROOM_MOTION:
            evidence.append("Movement in the room while nobody entered through the door - "
                            "possible intruder (window, other entrance) or someone hiding inside")
            is_security_indicator = True
        if unused_grants > 0:
            evidence.append(f"{int(unused_grants)} valid card scan(s) but nobody walked through "
                            "(changed their mind, or someone testing a card)")
        if interval_anomaly:
            evidence.append("Irregular inter-message timing jitter")

        if ml_category in ("attack", "fault") and ml_confidence > 0:
            evidence.append(f"AI classifier: {ml_category} ({ml_confidence:.0%} confidence)")

        # 3. Decision: rules first (explainable), then the AI where no rule matched.
        if unauthorized_count > 0 and (replay_count > 0 or pub_rate > FLOOD_MSGS_PER_SEC):
            category, severity, base_score = "CRITICAL_ATTACK", "CRITICAL", 90
        elif is_security_indicator:
            category, severity, base_score = "SUSPICIOUS_SECURITY_BEHAVIOUR", "HIGH", 75
        elif is_fault_indicator:
            category, severity, base_score = "DEVICE_HARDWARE_FAULT", "MEDIUM", 50
        elif ml_category == "attack" and ml_confidence >= 0.6:
            category, severity, base_score = "AI_SUSPECTED_ATTACK", "HIGH", 65
        elif ml_category == "fault" and ml_confidence >= 0.6:
            category, severity, base_score = "AI_SUSPECTED_FAULT", "MEDIUM", 45
        elif anomaly_detected:
            category, severity, base_score = "UNEXPLAINED_ANOMALY", "LOW", 35
            evidence.append("Statistical deviation flagged by Isolation Forest without a specific rule match")
        elif unused_grants > 0:
            category, severity, base_score = "ACCESS_NOT_USED", "LOW", 20
        else:
            category, severity, base_score = "NORMAL_OPERATION", "NONE", 5

        # decision_function is negative for anomalies: the further below 0, the higher the score.
        if anomaly_score < 0:
            risk_score = min(100, base_score + min(20, int(abs(anomaly_score) * 40)))
        else:
            risk_score = base_score

        return {
            "category": category,
            "severity": severity,
            "risk_score": risk_score,
            "evidence": evidence,
            "anomaly_detected": bool(anomaly_detected),
            "is_security_indicator": is_security_indicator,
            "is_fault_indicator": is_fault_indicator,
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
    print("Normal:", RiskAssessmentEngine.assess(False, anomaly_score=0.15))
    print("Sensor fault:", RiskAssessmentEngine.assess(True, anomaly_score=-0.12, is_sensor_stuck=True))
    print("Replay:", RiskAssessmentEngine.assess(True, anomaly_score=-0.25, replay_count=4))
    print("Brute force:", RiskAssessmentEngine.assess(True, window_sec=10, event_rate=20, access_denied=4))
    print("Tailgating:", RiskAssessmentEngine.assess(True, window_sec=10, event_rate=20, unauthorized_passes=1))
    print("Spoofed entry:", RiskAssessmentEngine.assess(False, window_sec=10, event_rate=20, entries_unconfirmed=1)["category"])
    print("Empty-room motion:", RiskAssessmentEngine.assess(False, window_sec=10, event_rate=20, motion_while_empty=5)["category"])
    print("Card, nobody at door:", RiskAssessmentEngine.assess(False, window_sec=10, event_rate=20, card_no_person=1)["category"])
    print("PIR noise (1 s):", RiskAssessmentEngine.assess(False, window_sec=10, event_rate=20, motion_while_empty=1)["category"])
