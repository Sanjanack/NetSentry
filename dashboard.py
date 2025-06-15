import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="NetSentry Dashboard", layout="wide")

st.title("🛡️ NetSentry Dashboard")
st.subheader("Live Network Alerts")

ALERT_FILE = "alerts.csv"

if os.path.exists(ALERT_FILE):
    df = pd.read_csv(ALERT_FILE)
    
    st.metric("Total Alerts", len(df))
    st.dataframe(df.tail(20), use_container_width=True)
    
    if not df.empty:
        st.bar_chart(df["Alert Type"].value_counts())
else:
    st.warning("Waiting for alerts...")

st.button("🔄 Refresh")
