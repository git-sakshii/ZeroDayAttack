"""Streamlit dashboard for scoring replayed network flow records."""

from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from .replay import load_frame, score_frame

st.set_page_config(page_title="ZeroDayShield Replay", page_icon="🛡️", layout="wide")
st.title("ZeroDayShield · Flow Replay")
st.caption("Scores flow records with a frozen benign-trained detector. An alert is an anomaly lead, not proof of an attack.")

model_file = st.sidebar.file_uploader("Model bundle (.joblib)", type=["joblib"])
flow_file = st.sidebar.file_uploader("Flow records (.csv or .parquet)", type=["csv", "parquet"])
if model_file and flow_file:
    try:
        bundle = joblib.load(model_file)
        if flow_file.name.lower().endswith(".parquet"):
            frame = pd.read_parquet(flow_file)
        else:
            frame = pd.read_csv(flow_file, low_memory=False)
        scored = score_frame(frame, bundle)
        alerts = scored[scored.alert]
        m1, m2, m3 = st.columns(3)
        m1.metric("Flows scored", f"{len(scored):,}")
        m2.metric("Alerts", f"{len(alerts):,}")
        m3.metric("Alert rate", f"{100 * len(alerts) / max(1, len(scored)):.2f}%")
        if "attack_family" in scored:
            st.subheader("Recall by supplied family (offline labeled replay only)")
            st.dataframe(scored.groupby("attack_family").alert.mean().rename("alert_rate").sort_values(ascending=False), use_container_width=True)
        st.subheader("Recent anomaly alerts")
        st.dataframe(alerts.head(500), use_container_width=True)
        st.download_button("Download scored replay CSV", scored.to_csv(index=False), "zerodayshield_alerts.csv", "text/csv")
        with st.expander("Model and input compatibility"):
            st.write({"model": bundle["model"], "target calibration FPR": bundle["target_fpr"],
                      "features": len(bundle["feature_names"]), "feature names": bundle["feature_names"]})
    except Exception as exc:
        st.error(f"Could not score this file: {exc}")
else:
    st.info("Upload a trained model bundle and a flow CSV/Parquet with the same feature columns used during training.")
    st.code("python -m zerodayshield.replay train --input data/processed/cicids2017_cleaned.parquet --output models/replay.joblib\npython -m streamlit run -m zerodayshield.dashboard", language="powershell")
