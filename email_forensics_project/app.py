import streamlit as st
import pandas as pd
import os
import subprocess
import sys

from reports.report.pdf_generator import create_pdf_report


# ==========================================================
# STREAMLIT CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="AI Browser & Email Forensics",
    page_icon="🔍",
    layout="wide"
)


# ==========================================================
# PROJECT PATHS
# ==========================================================

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(APP_DIR)

BROWSER_RESULT = os.path.join(
    PROJECT_DIR,
    "suspicious_urls_v3.csv"
)

EMAIL_REPORT_FILE = os.path.join(
    APP_DIR,
    "reports",
    "forensic_report.txt"
)

PDF_PATH = os.path.join(
    APP_DIR,
    "forensic_report.pdf"
)


# ==========================================================
# SESSION STATE
# ==========================================================

if "email_report_text" not in st.session_state:
    st.session_state.email_report_text = ""


# ==========================================================
# TITLE
# ==========================================================

st.title("🔍 AI-Based Browser & Email Forensics Engine")


# ==========================================================
# BROWSER FORENSICS
# ==========================================================

st.subheader("🌐 Browser Forensics")


if st.button("🔍 Run Browser Analysis"):

    with st.spinner("Running Browser Analysis..."):

        result = subprocess.run(
            [
                sys.executable,
                os.path.join(
                    PROJECT_DIR,
                    "browser",
                    "suspicious_urls.py"
                )
            ],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True
        )

    if result.returncode == 0:

        st.success(
            "Browser Analysis completed successfully!"
        )

        st.rerun()

    else:

        st.error(
            "Browser Analysis failed."
        )

        st.code(
            result.stderr
        )


# ==========================================================
# LOAD BROWSER RESULTS
# ==========================================================

if os.path.exists(BROWSER_RESULT):

    df = pd.read_csv(
        BROWSER_RESULT
    )

    total = len(df)

    phishing = sum(
        df["Status"]
        .astype(str)
        .str.upper()
        == "PHISHING"
    )

    benign = sum(
        df["Status"]
        .astype(str)
        .str.upper()
        == "BENIGN"
    )

    # ------------------------------------------------------
    # RISK LEVEL
    # ------------------------------------------------------

    if phishing == 0:

        risk_level = "LOW"

    elif phishing <= 3:

        risk_level = "MEDIUM"

    else:

        risk_level = "HIGH"


    # ------------------------------------------------------
    # METRICS
    # ------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total URLs",
        total
    )

    col2.metric(
        "🔴 Phishing URLs",
        phishing
    )

    col3.metric(
        "🟢 Benign URLs",
        benign
    )

    col4.metric(
        "⚠️ Risk Level",
        risk_level
    )


    st.divider()


    # ------------------------------------------------------
    # URL ANALYSIS
    # ------------------------------------------------------

    st.subheader(
        "URL Analysis"
    )

    status = st.selectbox(
        "Select Result",
        [
            "All",
            "PHISHING",
            "BENIGN"
        ]
    )


    if status == "PHISHING":

        filtered_df = df[
            df["Status"]
            .astype(str)
            .str.upper()
            == "PHISHING"
        ]

    elif status == "BENIGN":

        filtered_df = df[
            df["Status"]
            .astype(str)
            .str.upper()
            == "BENIGN"
        ]

    else:

        filtered_df = df


    st.dataframe(
        filtered_df,
        width="stretch",
        hide_index=True
    )


else:

    st.warning(
        "Browser analysis result not found."
    )

    st.write(
        "Click 'Run Browser Analysis' first."
    )

    # Default values so the PDF section does not crash
    total = 0
    phishing = 0
    benign = 0
    risk_level = "UNKNOWN"


# ==========================================================
# EMAIL FORENSICS
# ==========================================================

st.divider()

st.subheader(
    "📧 Email Forensics"
)

st.write(
    "Analyze the Gmail email using the Email Forensics module."
)


if st.button("🔍 Run Email Forensics"):

    with st.spinner(
        "Running Email Forensics..."
    ):

        result = subprocess.run(
            [
                sys.executable,
                "main.py"
            ],
            cwd=APP_DIR,
            capture_output=True,
            text=True
        )


    if result.returncode == 0:

        st.success(
            "Email Forensics completed successfully!"
        )


        # --------------------------------------------------
        # SAVE / LOAD EMAIL REPORT
        # --------------------------------------------------

        if os.path.exists(
            EMAIL_REPORT_FILE
        ):

            with open(
                EMAIL_REPORT_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                report = file.read()


            # Store COMPLETE report
            st.session_state.email_report_text = report


            # ------------------------------------------------
            # DISPLAY ONLY A PREVIEW
            # ------------------------------------------------

            st.subheader(
                "📄 Forensic Report"
            )

            st.text_area(
                "Email Forensics Report - Preview",
                report[:10000],
                height=400
            )


            if len(report) > 10000:

                st.info(
                    "The full email report is saved and will "
                    "be included in the PDF. Only the first "
                    "10,000 characters are displayed here."
                )


        else:

            st.warning(
                "Email forensic report file was not found."
            )


        # --------------------------------------------------
        # SHOW PROGRAM OUTPUT
        # --------------------------------------------------

        if result.stdout:

            with st.expander(
                "View Email Forensics Console Output"
            ):

                st.text(
                    result.stdout
                )


    else:

        st.error(
            "Email Forensics failed."
        )

        if result.stderr:

            st.code(
                result.stderr
            )


# ==========================================================
# PDF REPORT
# ==========================================================

st.divider()

st.subheader(
    "📄 Generate Forensic Report"
)


if st.button(
    "📄 Generate PDF Report"
):

    try:

        create_pdf_report(
            output_path=PDF_PATH,
            total_urls=total,
            phishing_urls=phishing,
            benign_urls=benign,
            risk_level=risk_level,
            email_report=st.session_state.email_report_text
        )


        st.success(
            "PDF report generated successfully!"
        )


        # --------------------------------------------------
        # DOWNLOAD PDF
        # --------------------------------------------------

        with open(
            PDF_PATH,
            "rb"
        ) as pdf_file:

            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_file,
                file_name="AI_Forensics_Report.pdf",
                mime="application/pdf"
            )


    except Exception as e:

        st.error(
            "PDF generation failed."
        )

        st.exception(e)