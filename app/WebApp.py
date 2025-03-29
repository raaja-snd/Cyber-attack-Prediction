import streamlit as st
import pandas as pd
import numpy as np
import joblib
from datetime import datetime

# Load trained model
model = joblib.load("Cyber_attack_predictor.pkl")

# Attack class mapping
attack_mapping = {
    0: "DDoS",
    1: "Intrusion",
    2: "Malware"
}

# Final 33 features used by model
important_features = [
    "Attack Month_5", "Attack Month_7", "Attack Month_6", "Network Segment_Segment B", "Browser_Opera",
    "Packet Type_Data", "Packet Weight_5", "Anomaly Rank_9", "Anomaly Rank_4", "Severity Level_Medium",
    "Traffic Type_HTTP", "Device_iPad", "Packet Weight_8", "Protocol_TCP", "Alerts/Warnings_Not Alerted",
    "Attack Month_10", "Attack Signature_Known Pattern B", "Device_iPhone", "Anomaly Rank_2",
    "IDS/IPS Alerts_No Alert Data", "Action Taken_Ignored", "Traffic Type_FTP", "Anomaly Rank_7",
    "Attack Month_9", "Attack Month_11", "Packet Weight_4", "Packet Weight_6", "Network Segment_Segment C",
    "Packet Weight_7", "Attack Month_2", "Attack Month_12", "Device_Windows", "Malware Indicators_Not Detected"
]

# Title
st.markdown("## 🛡️ Cyber Attack Prediction App")

# Description block
st.markdown("""
### 📊 Welcome!

This application allows you to detect the type of cyber attack based on raw network activity data.

- 🔍 **Input**: Raw CSV file containing various network attributes  
- 🧠 **Model**: Trained Random Forest classifier  
- 📌 **Prediction**: One of *DDoS*, *Intrusion*, or *Malware*

> _Note: Only the CSV upload option is enabled for better consistency and usability._
""")

# Upload section
st.markdown("---")
st.subheader("📁 Upload your CSV file")

uploaded_file = st.file_uploader("Choose a raw network data CSV file", type=["csv"])

# Preprocessing function
def preprocess_data(df):
    df["Firewall Logs"] = df["Firewall Logs"].replace("Log Data", "LogData")
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df["Attack Month"] = df["Timestamp"].dt.month

    def get_port_category(port):
        if port <= 49151:
            return "Registered"
        elif 49152 <= port <= 65535:
            return "Dynamic Private"
        else:
            return "Unknown"

    df["Source Port Type"] = df["Source Port"].apply(get_port_category)
    df["Destination Port Type"] = df["Destination Port"].apply(get_port_category)

    packet_bins = [0, 200, 400, 600, 800, 1000, 1200, 1400, np.inf]
    df["Packet Weight"] = pd.cut(df["Packet Length"], bins=packet_bins, labels=list(range(1, 9)), include_lowest=True)

    anomaly_bins = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, np.inf]
    df["Anomaly Rank"] = pd.cut(df["Anomaly Scores"], bins=anomaly_bins, labels=list(range(1, 12)), ordered=True, include_lowest=True)

    # Fill missing values
    df["Alerts/Warnings"] = df["Alerts/Warnings"].fillna("Not Alerted")
    df["Malware Indicators"] = df["Malware Indicators"].fillna("Not Detected")
    df["IDS/IPS Alerts"] = df["IDS/IPS Alerts"].fillna("No Alert Data")
    df["Proxy Information"] = df["Proxy Information"].fillna("No Proxy")

    # Extract browser type
    df["Browser"] = df["Device Information"].apply(lambda x: "Opera" if "Opera" in str(x) else "")

    # Extract device type
    def get_device(x):
        x = str(x).lower()
        if "ipad" in x:
            return "iPad"
        elif "iphone" in x:
            return "iPhone"
        elif "windows" in x:
            return "Windows"
        else:
            return ""
    df["Device"] = df["Device Information"].apply(get_device)

    # Drop unneeded columns
    cols_to_drop = ["Timestamp", "Source Port", "Destination Port", "Packet Length", "Anomaly Scores",
                    "Firewall Logs", "Destination Port Type", "Device Information"]
    df = df.drop(columns=[col for col in cols_to_drop if col in df.columns], errors='ignore')

    # One-hot encoding
    cat_cols = ["Protocol", "Packet Type", "Traffic Type", "Malware Indicators", "Alerts/Warnings",
                "Attack Signature", "Action Taken", "Severity Level", "Network Segment", "IDS/IPS Alerts",
                "Browser", "Packet Weight", "Anomaly Rank", "Device", "Attack Month"]
    df = pd.get_dummies(df, columns=cat_cols, drop_first=True)

    # Ensure all 33 features are present
    for feat in important_features:
        if feat not in df.columns:
            df[feat] = 0

    return df[important_features]

# Processing CSV
if uploaded_file is not None:
    st.success("✅ File successfully uploaded!")
    df_raw = pd.read_csv(uploaded_file)
    st.write("📄 Preview of uploaded data:")
    st.dataframe(df_raw)

    try:
        df_processed = preprocess_data(df_raw)

        if df_processed.shape[1] != 33:
            st.error(f"❌ The model expects 33 features, but got {df_processed.shape[1]}.")
        else:
            predictions = model.predict(df_processed)
            df_raw["Predicted Attack Type"] = [attack_mapping[p] for p in predictions]

            st.success("🎯 Prediction completed!")
            st.markdown("### 📈 Prediction Results")
            st.dataframe(df_raw[["Timestamp", "Predicted Attack Type"]])

            csv = df_raw.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download Results as CSV", data=csv, file_name="predictions.csv", mime="text/csv")

    except Exception as e:
        st.error(f"⚠️ Error during preprocessing or prediction: {e}")
