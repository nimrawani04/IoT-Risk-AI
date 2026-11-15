"""
Plain-language incident reports from a local LLM (Ollama).

The detection itself is done by the models and rules in detector.py / risk.py;
this only turns one detection's evidence into a short report a person can act on.
Runs fully offline against Ollama on the laptop.

Settings (environment variables): OLLAMA_URL (default http://localhost:11434),
OLLAMA_MODEL (default qwen2.5:7b).
"""

import os
import json
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")

SYSTEM_PROMPT = """You are the security analyst for a lab smart-room IoT system:
an RFID door (RC522 reader + PIR motion), a room node (ultrasonic distance at the door,
IR beam counting doorway crossings, MQ-135 air quality), two Arduinos sending data
through a Raspberry Pi MQTT gateway to a monitoring laptop.

You receive one detection as JSON. Write a short incident report using ONLY those facts.
Do not invent devices, people, times or numbers. If the evidence is weak, say so.

Format exactly:
What happened: <1-2 sentences>
Fault or attack: <fault / attack / unclear> - <one-sentence reason>
Do now:
- <action>
- <action>
Keep it under 110 words."""


def generate_report(detection, timeout=60):
    facts = {k: detection.get(k) for k in (
        "window_start", "risk_category", "severity", "risk_score", "evidence",
        "ml_scenario", "ml_confidence", "reasons", "anomaly_score",
    )}
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(facts, default=str)},
        ],
        "stream": False,
        "options": {"temperature": 0.2},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)["message"]["content"].strip()
    except Exception as e:
        print(f"[Report] Ollama unavailable ({e}); detection saved without a report.")
        return None


if __name__ == "__main__":
    print(generate_report({
        "window_start": "2026-11-15T10:00:00+00:00",
        "risk_category": "SUSPICIOUS_SECURITY_BEHAVIOUR", "severity": "HIGH", "risk_score": 88,
        "evidence": "4 denied card scans - possible card brute-force; AI classifier: attack (91% confidence)",
        "ml_scenario": "attack_brute_force", "ml_confidence": 0.91,
        "reasons": "denied scans high (4 vs normal 0)", "anomaly_score": -0.21,
    }))
