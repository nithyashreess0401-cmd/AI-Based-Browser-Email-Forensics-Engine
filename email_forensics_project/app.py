import streamlit as st
import pandas as pd
import os
import subprocess
import sys

st.set_page_config(
    page_title="AI Browser & Email Forensics",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 AI-Based Browser & Email Forensics Engine")

# ==========================================================
# BROWSER FORENSICS
# ==========================================================

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


# ==========================================================
# EMAIL FORENSICS
# ==========================================================

st.divider()

st.subheader("📧 Email Forensics")

st.write(
    "Analyze the Gmail email using the Email Forensics module."
)

if st.button("🔍 Run Email Forensics"):

    with st.spinner("Running Email Forensics..."):

        result = subprocess.run(
            [sys.executable, "main.py"],
            capture_output=True,
            text=True
        )

    if result.returncode == 0:

        st.success("Email Forensics completed successfully!")

        st.subheader("Analysis Output")

        st.text(result.stdout)

        report_file = "reports/forensic_report.txt"

        if os.path.exists(report_file):

            st.subheader("📄 Forensic Report")

            with open(
                report_file,
                "r",
                encoding="utf-8"
            ) as file:

                report = file.read()

            st.text_area(
                "Email Forensics Report",
                report,
                height=400
            )

    else:

        st.error("Email Forensics failed.")

        st.code(result.stderr)