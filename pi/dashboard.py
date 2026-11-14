"""
Streamlit Dashboard for IoT Behavioural Risk Assessment and Anomaly Detection.
Provides real-time visibility into physical sensor readings, network-layer events,
Isolation Forest anomaly detection, and transparent evidence-based risk assessments.
"""

import os
import json
import sqlite3
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

DB_PATH = "data/telemetry.db"
DETECTIONS_PATH = "data/detections.csv"

st.set_page_config(
    page_title="IoT Behavioural Risk Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        padding: 16px;
        border-radius: 8px;
        border: 1px solid #334155;
    }
    .badge-critical { background-color: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #f97316; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #eab308; color: black; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #3b82f6; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-normal { background-color: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI-Based IoT Behavioural Risk Assessment")
st.caption(
    "Experimental Cross-Layer Behavioral Vulnerability & Risk Prediction Framework. "
    "Differentiates sensor malfunctions from security attack scenarios using combined physical & network evidence."
)

# Sidebar controls
st.sidebar.header("Navigation & Settings")
auto_refresh = st.sidebar.checkbox("Auto-refresh data", value=True)
refresh_sec = st.sidebar.slider("Refresh every (seconds)", 1, 30, 3, disabled=not auto_refresh)

view_mode = st.sidebar.radio("Select View", ["Overview & Alerts", "Sensor Telemetry", "Network Telemetry", "Model & Experiments"])

# Data Loading
def load_all_telemetry():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(), pd.DataFrame()

    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute("SELECT received_at, device, event, payload FROM telemetry ORDER BY id DESC LIMIT 3000").fetchall()
    except Exception:
        rows = []
    
    try:
        df_net = pd.read_sql_query("SELECT * FROM network_telemetry ORDER BY id DESC LIMIT 3000", conn)
    except Exception:
        df_net = pd.DataFrame()

    conn.close()

    records = []
    for received_at, device, event, payload in rows:
        try:
            item = json.loads(payload)
            item["received_at"] = received_at
            item["device"] = device
            item["event"] = event
            records.append(item)
        except Exception:
            continue

    df_sensor = pd.DataFrame(records)
    return df_sensor, df_net


# Only this fragment reruns on the timer, so the sidebar and page layout stay put
# instead of the whole page redrawing (and flickering) on every refresh.
@st.fragment(run_every=refresh_sec if auto_refresh else None)
def live_view():
    df_sensor, df_net = load_all_telemetry()
    detections_exist = os.path.exists(DETECTIONS_PATH)
    df_det = pd.read_csv(DETECTIONS_PATH) if detections_exist else pd.DataFrame()

    # Top Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Sensor Observations", len(df_sensor))
    col2.metric("Network Packets", len(df_net))
    col3.metric("Active Devices", df_sensor["device"].nunique() if not df_sensor.empty else 0)

    if not df_det.empty and "risk_category" in df_det.columns:
        anom_count = int((df_det["status"] == "Anomalous").sum())
        col4.metric("Flagged Windows", anom_count, delta=f"{anom_count} anomalies", delta_color="inverse")
    else:
        col4.metric("Flagged Windows", 0)

    st.divider()

    # VIEW 1: Overview & Alerts
    if view_mode == "Overview & Alerts":
        st.subheader("🚨 Risk & Vulnerability Assessment Feed")
        
        if df_det.empty:
            st.info("No detection results found yet. Train or run inference with `python pi/detector.py predict` or run experiments.")
        else:
            # Latest Risk Status
            latest = df_det.iloc[-1]
            cat = latest.get("risk_category", "UNKNOWN")
            score = latest.get("risk_score", 0)
            sev = latest.get("severity", "LOW")
            evidence = latest.get("evidence_notes", "No evidence recorded")

            st.markdown(f"""
            ### Current Window Assessment: **{cat}** (Risk Score: `{score}/100` | Severity: `{sev}`)
            **Evidence Trail:** {evidence}
            """)

            # Risk Score Gauge / Trend
            fig_score = px.line(
                df_det,
                x="received_at",
                y="risk_score",
                title="Real-time Risk Score Trajectory (0 = Benign, 100 = High Risk Attack)",
                color_discrete_sequence=["#ef4444"],
                markers=True
            )
            fig_score.update_layout(yaxis_range=[0, 105], template="plotly_dark")
            st.plotly_chart(fig_score, use_container_width=True)

            # Recent Detection Table
            st.subheader("Recent Evaluation Windows")
            display_cols = [c for c in ["received_at", "device", "status", "risk_category", "severity", "risk_score", "evidence_notes"] if c in df_det.columns]
            st.dataframe(df_det[display_cols].tail(20), use_container_width=True)

    # VIEW 2: Sensor Telemetry
    elif view_mode == "Sensor Telemetry":
        st.subheader("📊 Physical Sensor Streams")
        if df_sensor.empty:
            st.warning("No physical sensor readings collected yet.")
        else:
            colA, colB = st.columns(2)

            if "mq135_raw" in df_sensor.columns:
                gas_df = df_sensor.dropna(subset=["mq135_raw"]).copy()
                if not gas_df.empty:
                    fig_gas = px.line(gas_df.head(200), x="received_at", y="mq135_raw", title="Arduino 1 — MQ-135 Gas Sensor ADC Output", template="plotly_dark")
                    colA.plotly_chart(fig_gas, use_container_width=True)

            if "distance_cm" in df_sensor.columns:
                dist_df = df_sensor[df_sensor["distance_cm"] >= 0].head(200).copy()
                if not dist_df.empty:
                    fig_dist = px.line(dist_df, x="received_at", y="distance_cm", title="Arduino 1 — Ultrasonic Distance (cm)", template="plotly_dark", color_discrete_sequence=["#06b6d4"])
                    colB.plotly_chart(fig_dist, use_container_width=True)

            colC, colD = st.columns(2)
            if "motion" in df_sensor.columns:
                mot_df = df_sensor.dropna(subset=["motion"]).head(200).copy()
                if not mot_df.empty:
                    fig_mot = px.bar(mot_df, x="received_at", y="motion", title="Arduino 2 — PIR Motion Events", template="plotly_dark", color_discrete_sequence=["#10b981"])
                    colC.plotly_chart(fig_mot, use_container_width=True)

            if "ir_count" in df_sensor.columns:
                btn_df = df_sensor.dropna(subset=["ir_count"]).head(200).copy()
                if not btn_df.empty:
                    fig_btn = px.bar(btn_df, x="received_at", y="ir_count", title="Arduino 1 — IR Beam Breaks", template="plotly_dark", color_discrete_sequence=["#f59e0b"])
                    colD.plotly_chart(fig_btn, use_container_width=True)

    # VIEW 3: Network Telemetry
    elif view_mode == "Network Telemetry":
        st.subheader("🌐 MQTT Communication & Attack Indicators")
        if df_net.empty:
            st.info("No MQTT network packets recorded yet. Start `pi/mqtt_monitor.py` or run synthetic experiments.")
        else:
            colX, colY = st.columns(2)
            colX.metric("Replay Anomalies Detected", int(df_net["is_replay"].sum()) if "is_replay" in df_net.columns else 0)
            colY.metric("Unauthorized / Rogue Messages", int(df_net["is_unauthorized"].sum()) if "is_unauthorized" in df_net.columns else 0)

            st.subheader("Live Network Packets")
            st.dataframe(df_net.head(50), use_container_width=True)

    # VIEW 4: Model & Experiments
    elif view_mode == "Model & Experiments":
        st.subheader("🧪 Research Experimentation & Benchmarking")
        st.markdown("""
        This section validates the **Research Hypothesis**:
        > *Combining device-level sensor features and network-level communication features improves the detection and classification of IoT faults vs attacks compared to sensor-only models.*
        """)

        st.code("""
        # Generate controlled experimental dataset
        python experiments/generate_test_data.py --duration 120

        # Run research benchmark and evaluate Sensor-Only vs Network-Only vs Cross-Layer
        python experiments/evaluate.py
        """, language="bash")

        if os.path.exists("data/evaluation_summary.csv"):
            st.subheader("Benchmark Comparison Results")
            eval_df = pd.read_csv("data/evaluation_summary.csv")
            st.dataframe(eval_df, use_container_width=True)
        else:
            st.info("Run `python experiments/evaluate.py` to generate the evaluation benchmark.")


live_view()
