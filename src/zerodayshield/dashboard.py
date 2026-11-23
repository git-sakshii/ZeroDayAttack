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
compare_all = st.sidebar.checkbox("Compare all available local models")
flow_file = st.sidebar.file_uploader("Flow records (.csv or .parquet)", type=["csv", "parquet"])
if compare_all and flow_file:
    try:
        if flow_file.name.lower().endswith(".parquet"):
            frame = pd.read_parquet(flow_file)
        else:
            frame = pd.read_csv(flow_file, low_memory=False)
        rows = []
        scored_by_model = {}
        for model_name, model_path in local_models.items():
            if not model_path.exists():
                continue
            bundle = joblib.load(model_path)
            scored = score_frame(frame, bundle)
            scored_by_model[model_name] = scored
            alerts = scored["alert"].astype(bool)
            if "Label" in frame:
                attack_rows = frame["Label"].astype(str).str.casefold() != "benign"
                benign_rows = ~attack_rows
                attack_recall = float(alerts[attack_rows].mean()) if attack_rows.any() else float("nan")
                benign_fpr = float(alerts[benign_rows].mean()) if benign_rows.any() else float("nan")
            else:
                attack_recall = benign_fpr = float("nan")
            rows.append({"Model": model_name, "Alerts": int(alerts.sum()),
                         "Alert rate": float(alerts.mean()), "Attack recall": attack_recall,
                         "Benign FPR": benign_fpr})
        comparison = pd.DataFrame(rows)
        st.subheader("Model comparison on this replay file")
        if "Label" not in frame:
            st.info("This file has no labels, so attack recall and benign FPR cannot be calculated.")
        else:
            st.caption("Labels are used only to calculate these summary metrics after scoring. A balanced sample changes attack prevalence; treat results as exploratory.")
        st.dataframe(comparison.style.format({"Alert rate": "{:.2%}", "Attack recall": "{:.2%}", "Benign FPR": "{:.2%}"}), use_container_width=True)
        chart_columns = [c for c in ["Attack recall", "Benign FPR"] if c in comparison]
        if chart_columns:
            st.bar_chart(comparison.set_index("Model")[chart_columns])
        st.download_button("Download comparison CSV", comparison.to_csv(index=False), "model_comparison.csv", "text/csv")
    except Exception as exc:
        st.error(f"Could not compare models: {exc}")
elif (model_file or selected_model != "Upload a model") and flow_file:
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
    st.code("python -m zerodayshield.replay train --input data/processed/cicids2017_cleaned.parquet --output models/replay.joblib\npython -m streamlit run src/zerodayshield/dashboard.py", language="powershell")
