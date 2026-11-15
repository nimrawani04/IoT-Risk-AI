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

    # The frames above are capped at 3000 rows for charts; the metrics need the real totals.
    totals = {}
    for table in ("telemetry", "network_telemetry"):
        try:
            totals[table] = conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0] or 0
        except Exception:
            totals[table] = 0
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
    return df_sensor, df_net, totals


def load_detections(limit=360):
    """Latest AI verdicts (360 x 10 s windows = the last hour), oldest first."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(f"SELECT * FROM detections ORDER BY window_start DESC LIMIT {int(limit)}", conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    if not df.empty:
        df["window_start"] = pd.to_datetime(df["window_start"], utc=True, format="ISO8601")
        df = df.sort_values("window_start")
    return df


SEVERITY_BOX = {"CRITICAL": st.error, "HIGH": st.error, "MEDIUM": st.warning, "LOW": st.info, "NONE": st.success}


# Only this fragment reruns on the timer, so the sidebar and page layout stay put
# instead of the whole page redrawing (and flickering) on every refresh.
@st.fragment(run_every=refresh_sec if auto_refresh else None)
def live_view():
    df_sensor, df_net, totals = load_all_telemetry()
    df_det = load_detections()

    # Top Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Sensor Observations", f"{totals.get('telemetry', 0):,}")
    col2.metric("Network Packets", f"{totals.get('network_telemetry', 0):,}")
    col3.metric("Active Devices", df_sensor["device"].nunique() if not df_sensor.empty else 0)
    flagged = int((df_det["severity"] != "NONE").sum()) if not df_det.empty else 0
    col4.metric("Flagged Windows (last hour)", flagged)

    st.divider()

    # VIEW 1: Overview & Alerts
    if view_mode == "Overview & Alerts":
        st.subheader("🤖 Live AI Assessment")

        if df_det.empty:
            st.info("No AI verdicts yet. Train with `python pi/detector.py train`, then start "
                    "`python pi/detector.py live --reports`.")
        else:
            latest = df_det.iloc[-1]
            age = (pd.Timestamp.now(tz="UTC") - latest["window_start"]).total_seconds()
            if age > 60:
                st.warning(f"Latest verdict is {age:.0f}s old. Is `detector.py live` running?")

            box = SEVERITY_BOX.get(latest["severity"], st.info)
            box(f"**{latest['risk_category']}** | risk {latest['risk_score']}/100 | "
                f"severity {latest['severity']}  \n{latest['evidence']}")

            colL, colR = st.columns(2)
            if latest.get("ml_scenario"):
                colL.metric("AI classifier says", latest["ml_scenario"].replace("_", " "),
                            f"{latest['ml_confidence']:.0%} confident", delta_color="off")
            else:
                colL.metric("AI classifier says", "not trained yet")
            colR.metric("Anomaly score", f"{latest['anomaly_score']:+.3f}",
                        "unusual" if latest["is_anomaly"] else "normal",
                        delta_color="inverse" if latest["is_anomaly"] else "normal")
            if latest.get("reasons"):
                st.caption(f"Why: {latest['reasons']}")

            fig_score = px.line(df_det, x="window_start", y="risk_score", markers=True,
                                title="Risk score (0 = normal, 100 = critical attack)",
                                color_discrete_sequence=["#ef4444"], template="plotly_dark")
            fig_score.update_layout(yaxis_range=[0, 105])
            fig_anom = px.line(df_det, x="window_start", y="anomaly_score",
                               title="Isolation Forest anomaly score (below 0 = unusual)",
                               color_discrete_sequence=["#a78bfa"], template="plotly_dark")
            fig_anom.add_hline(y=0, line_dash="dash", line_color="#94a3b8")
            colA, colB = st.columns(2)
            colA.plotly_chart(fig_score, use_container_width=True)
            colB.plotly_chart(fig_anom, use_container_width=True)

            reports = df_det[df_det["report"].notna()].tail(5).iloc[::-1]
            st.subheader("📝 AI Incident Reports (local LLM)")
            if reports.empty:
                st.caption("None yet. Reports are written for HIGH/CRITICAL incidents when "
                           "`detector.py live --reports` is running with Ollama.")
            for _, r in reports.iterrows():
                with st.expander(f"{r['window_start']:%H:%M:%S} · {r['risk_category']} · risk {r['risk_score']}"):
                    st.markdown(r["report"])

            st.subheader("Recent windows")
            cols = ["window_start", "risk_category", "severity", "risk_score", "ml_scenario",
                    "ml_confidence", "anomaly_score", "reasons", "evidence"]
            st.dataframe(df_det[cols].tail(20).iloc[::-1], use_container_width=True, hide_index=True)

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
                    fig_gas = px.line(gas_df.head(200), x="received_at", y="mq135_raw", title="Room node — MQ-135 Gas Sensor ADC Output", template="plotly_dark")
                    colA.plotly_chart(fig_gas, use_container_width=True)

            if "distance_cm" in df_sensor.columns:
                dist_df = df_sensor[df_sensor["distance_cm"] >= 0].head(200).copy()
                if not dist_df.empty:
                    fig_dist = px.line(dist_df, x="received_at", y="distance_cm", title="Door node — Corridor Ultrasonic Distance (cm)", template="plotly_dark", color_discrete_sequence=["#06b6d4"])
                    colB.plotly_chart(fig_dist, use_container_width=True)

            colC, colD = st.columns(2)
            if "motion" in df_sensor.columns:
                mot_df = df_sensor.dropna(subset=["motion"]).head(200).copy()
                if not mot_df.empty:
                    fig_mot = px.bar(mot_df, x="received_at", y="motion", title="Room node — PIR Motion Events", template="plotly_dark", color_discrete_sequence=["#10b981"])
                    colC.plotly_chart(fig_mot, use_container_width=True)

            if "ir_count" in df_sensor.columns:
                btn_df = df_sensor.dropna(subset=["ir_count"]).head(200).copy()
                if not btn_df.empty:
                    fig_btn = px.bar(btn_df, x="received_at", y="ir_count", title="Door node — IR Doorway Crossings", template="plotly_dark", color_discrete_sequence=["#f59e0b"])
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
# 1. Record labelled sessions on the real hardware (repeat each a few times)
python experiments/record_session.py --list
python experiments/record_session.py normal --minutes 10
python experiments/record_session.py attack_brute_force --minutes 2

# 2. Train the anomaly model + fault/attack classifier
python pi/detector.py train

# 3. Evaluate Sensor-only vs Network-only vs Door-only vs Cross-layer (split by session)
python experiments/evaluate_sessions.py
""", language="bash")

        if os.path.exists("data/evaluation_sessions.csv"):
            st.subheader("Results on recorded sessions")
            st.dataframe(pd.read_csv("data/evaluation_sessions.csv"), use_container_width=True, hide_index=True)
        else:
            st.info("Run `python experiments/evaluate_sessions.py` after recording sessions.")


live_view()
