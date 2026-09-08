import streamlit as st
import pandas as pd
import os

st.set_page_config(
    page_title="AI Browser & Email Forensics",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 AI-Based Browser & Email Forensics Engine")
st.subheader("🌐 Browser Forensics")

file = "browser_forensics_final.csv"

if os.path.exists(file):

    df = pd.read_csv(file)

    total = len(df)
    high = sum(df["Risk Level"] == "High")
    medium = sum(df["Risk Level"] == "Medium")
    low = sum(df["Risk Level"] == "Low")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total URLs", total)
    col2.metric("🔴 High Risk", high)
    col3.metric("🟠 Medium Risk", medium)
    col4.metric("🟢 Low Risk", low)

    st.divider()

    st.subheader("Risk Filter")

    risk = st.selectbox(
        "Select Risk Level",
        ["All", "High", "Medium", "Low"]
    )

    if risk != "All":
        filtered_df = df[df["Risk Level"] == risk]
    else:
        filtered_df = df

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

else:
    st.error(
        "browser_forensics_final.csv not found. "
        "Please run the browser analysis first."
    )