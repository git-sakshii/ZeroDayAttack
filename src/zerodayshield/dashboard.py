"""Streamlit dashboard for scoring replayed network flow records."""

from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

# Streamlit executes this file as a script, so a package-relative import has
# no parent package. Use the installed package's absolute import instead.
from zerodayshield.replay import load_frame, score_frame

st.set_page_config(page_title="ZeroDayShield Replay", page_icon="🛡️", layout="wide")
st.title("ZeroDayShield · Flow Replay")
st.caption("Scores flow records with a frozen benign-trained detector. An alert is an anomaly lead, not proof of an attack.")

model_file = st.sidebar.file_uploader("Model bundle (.joblib)", type=["joblib"])
local_models = {
    "Isolation Forest": Path("models/replay.joblib"),
    "PCA reconstruction": Path("models/replay_pca.joblib"),
    "IF + PCA score fusion": Path("models/replay_fusion.joblib"),
    "Autoencoder": Path("models/replay_autoencoder.joblib"),
}
available_models = [name for name, path in local_models.items() if path.exists()]
selected_model = st.sidebar.selectbox("Or select a locally trained model", ["Upload a model"] + available_models)
flow_file = st.sidebar.file_uploader("Flow records (.csv or .parquet)", type=["csv", "parquet"])
if (model_file or selected_model != "Upload a model") and flow_file:
    try:
        bundle = joblib.load(model_file if model_file else local_models[selected_model])
        if flow_file.name.lower().endswith(".parquet"):
            frame = pd.read_parquet(flow_file)
        else:
            frame = pd.read_csv(flow_file, low_memory=False)
        scored = score_frame(frame, bundle)
        alerts = scored[scored.alert]
        m1, m2, m3 = st.columns(3)
        model_display = {"isolation_forest": "Isolation Forest", "pca": "PCA reconstruction",
                         "rank_fusion": "IF + PCA score fusion", "autoencoder": "Autoencoder"}
        m1.metric("Model", model_display.get(bundle["model"], bundle["model"]))
        m2.metric("Alerts", f"{len(alerts):,}")
        m3.metric("Flows scored", f"{len(scored):,}")
        st.caption(f"Alert rate: {100 * len(alerts) / max(1, len(scored)):.2f}% · Calibration target: {bundle['target_fpr']:.1%} FPR")
        if "Label" in scored:
            known_attack = scored["Label"].astype(str).str.casefold() != "benign"
            benign_rows = ~known_attack
            attack_recall = float(scored.loc[known_attack, "alert"].mean()) if known_attack.any() else float("nan")
            benign_fpr = float(scored.loc[benign_rows, "alert"].mean()) if benign_rows.any() else float("nan")
            st.subheader("Replay check against supplied labels")
            st.caption("Labels are only used here to summarize this labeled replay file; the detector did not use them to create its alerts.")
            c1, c2, c3 = st.columns(3)
            c1.metric("Labeled attack flows", f"{int(known_attack.sum()):,}")
            c2.metric("Attack recall in this file", f"{attack_recall:.1%}" if known_attack.any() else "N/A")
            c3.metric("Benign false-positive rate", f"{benign_fpr:.2%}" if benign_rows.any() else "N/A")
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
