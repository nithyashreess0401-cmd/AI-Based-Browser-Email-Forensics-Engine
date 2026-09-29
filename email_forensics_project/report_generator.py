import email
from email import policy
import re
from urllib.parse import urlparse
import pandas as pd
import os
from datetime import datetime


# ============================================================
# PATH SETUP
# ============================================================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(CURRENT_DIR)

EMAIL_FILE = os.path.join(
    CURRENT_DIR,
    "emails",
    "gmail_message.eml"
)

BROWSER_RESULT_FILE = os.path.join(
    PROJECT_DIR,
    "suspicious_urls_v3.csv"
)

REPORT_DIR = os.path.join(
    CURRENT_DIR,
    "reports"
)

REPORT_FILE = os.path.join(
    REPORT_DIR,
    "forensic_report.txt"
)

# Create reports folder automatically
os.makedirs(REPORT_DIR, exist_ok=True)


# ============================================================
# EMAIL ANALYSIS
# ============================================================

print("==========================================")
print("   AI BROWSER & EMAIL FORENSICS ENGINE")
print("==========================================")

print("\nAnalyzing email...")


with open(EMAIL_FILE, "rb") as file:

    msg = email.message_from_binary_file(
        file,
        policy=policy.default
    )


# ------------------------------------------------------------
# GET EMAIL BODY
# ------------------------------------------------------------

body = ""

if msg.is_multipart():

    for part in msg.walk():

        if part.get_content_type() == "text/plain":

            try:
                body += part.get_content()

            except Exception:
                pass

else:

    try:
        body = msg.get_content()

    except Exception:
        body = ""


# ------------------------------------------------------------
# EXTRACT EMAIL URLS
# ------------------------------------------------------------

urls = re.findall(
    r'https?://[^\s<>"\']+',
    body
)


# ------------------------------------------------------------
# EMAIL URL ANALYSIS
# ------------------------------------------------------------

email_url_results = []

suspicious_email_count = 0


for url in urls:

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    suspicious = False

    reasons = []


    # IP address
    if re.match(
        r'^\d{1,3}(\.\d{1,3}){3}$',
        domain
    ):

        suspicious = True

        reasons.append(
            "Uses an IP address"
        )


    # @ symbol
    if "@" in url:

        suspicious = True

        reasons.append(
            "Contains @ symbol"
        )


    # Long URL
    if len(url) > 150:

        suspicious = True

        reasons.append(
            "Unusually long URL"
        )


    # Suspicious keywords
    suspicious_words = [

        "login",
        "verify",
        "account",
        "password",
        "urgent",
        "security",
        "confirm"

    ]


    for word in suspicious_words:

        if word in url.lower():

            suspicious = True

            reasons.append(
                f"Contains suspicious keyword: {word}"
            )

            break


    if suspicious:

        suspicious_email_count += 1

        status = "SUSPICIOUS"

    else:

        status = "NO OBVIOUS SUSPICIOUS PATTERN"


    email_url_results.append({

        "url": url,

        "status": status,

        "reasons": reasons

    })


# ------------------------------------------------------------
# EMAIL RISK
# ------------------------------------------------------------

if suspicious_email_count > 0:

    email_risk = "HIGH"

elif len(urls) > 0:

    email_risk = "LOW"

else:

    email_risk = "LOW"


print("Email analysis completed.")


# ============================================================
# BROWSER ANALYSIS RESULTS
# ============================================================

print("\nLoading browser analysis results...")


browser_available = False

browser_df = None

total_browser_urls = 0

benign_browser_urls = 0

phishing_browser_urls = 0

browser_risk = "UNKNOWN"


if os.path.exists(BROWSER_RESULT_FILE):

    try:

        browser_df = pd.read_csv(
            BROWSER_RESULT_FILE
        )


        required_columns = [
            "URL",
            "Status",
            "Confidence"
        ]


        if all(
            column in browser_df.columns
            for column in required_columns
        ):

            browser_available = True


            total_browser_urls = len(
                browser_df
            )


            benign_browser_urls = (
                browser_df["Status"]
                .astype(str)
                .str.upper()
                .eq("BENIGN")
                .sum()
            )


            phishing_browser_urls = (
                browser_df["Status"]
                .astype(str)
                .str.upper()
                .eq("PHISHING")
                .sum()
            )


            if phishing_browser_urls == 0:

                browser_risk = "LOW"

            elif phishing_browser_urls <= 3:

                browser_risk = "MEDIUM"

            else:

                browser_risk = "HIGH"


            print(
                "Browser analysis results loaded successfully."
            )

        else:

            print(
                "Browser CSV does not contain expected columns."
            )


    except Exception as error:

        print(
            "Could not read browser results:",
            error
        )

else:

    print(
        "suspicious_urls_v3.csv was not found."
    )


# ============================================================
# OVERALL RISK
# ============================================================

risk_values = {

    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "UNKNOWN": 0

}


email_score = risk_values.get(
    email_risk,
    0
)

browser_score = risk_values.get(
    browser_risk,
    0
)


overall_score = max(
    email_score,
    browser_score
)


if overall_score == 3:

    overall_risk = "HIGH"

elif overall_score == 2:

    overall_risk = "MEDIUM"

else:

    overall_risk = "LOW"


# ============================================================
# GENERATE REPORT
# ============================================================

print("\nGenerating forensic report...")


with open(
    REPORT_FILE,
    "w",
    encoding="utf-8"
) as report:


    report.write(
        "============================================================\n"
    )

    report.write(
        "       AI-BASED BROWSER & EMAIL FORENSICS REPORT\n"
    )

    report.write(
        "============================================================\n\n"
    )


    report.write(
        f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

    report.write(
        "Analysis Type: Email + Browser Digital Forensics\n\n"
    )


    # ========================================================
    # EMAIL SECTION
    # ========================================================

    report.write(
        "============================================================\n"
    )

    report.write(
        "                    EMAIL FORENSICS\n"
    )

    report.write(
        "============================================================\n\n"
    )


    report.write(
        "----- EMAIL DETAILS -----\n"
    )


    report.write(
        f"From: {msg['From'] or 'Not Found'}\n"
    )

    report.write(
        f"To: {msg['To'] or 'Not Found'}\n"
    )

    report.write(
        f"Reply-To: {msg['Reply-To'] or 'Not Found'}\n"
    )

    report.write(
        f"Subject: {msg['Subject'] or 'Not Found'}\n"
    )

    report.write(
        f"Date: {msg['Date'] or 'Not Found'}\n"
    )

    report.write(
        f"Message-ID: {msg['Message-ID'] or 'Not Found'}\n\n"
    )


    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    report.write(
        "----- EMAIL AUTHENTICATION -----\n"
    )


    spf = msg["Received-SPF"]

    dkim = msg["DKIM-Signature"]

    authentication_results = msg[
        "Authentication-Results"
    ]


    report.write(
        f"SPF: {spf if spf else 'Not Found'}\n"
    )

    report.write(
        f"DKIM: {'Found' if dkim else 'Not Found'}\n"
    )

    report.write(
        f"Authentication Results: "
        f"{authentication_results if authentication_results else 'Not Found'}\n\n"
    )


    # --------------------------------------------------------
    # EMAIL URL SUMMARY
    # --------------------------------------------------------

    report.write(
        "----- EMAIL URL SUMMARY -----\n"
    )


    report.write(
        f"Total URLs Found: {len(urls)}\n"
    )

    report.write(
        f"Suspicious URLs: {suspicious_email_count}\n"
    )

    report.write(
        f"Email Risk Level: {email_risk}\n\n"
    )


    # --------------------------------------------------------
    # EMAIL URL DETAILS
    # --------------------------------------------------------

    report.write(
        "----- EMAIL URL DETAILS -----\n"
    )


    if not email_url_results:

        report.write(
            "No URLs were found in the email.\n"
        )

    else:

        for number, result in enumerate(
            email_url_results,
            start=1
        ):

            report.write(
                f"\n[{number}] URL: {result['url']}\n"
            )

            report.write(
                f"Status: {result['status']}\n"
            )


            if result["reasons"]:

                report.write(
                    "Reasons:\n"
                )

                for reason in result["reasons"]:

                    report.write(
                        f"  - {reason}\n"
                    )


    # ========================================================
    # BROWSER SECTION
    # ========================================================

    report.write(
        "\n\n============================================================\n"
    )

    report.write(
        "                   BROWSER FORENSICS\n"
    )

    report.write(
        "============================================================\n\n"
    )


    if browser_available:


        report.write(
            "----- BROWSER ANALYSIS SUMMARY -----\n"
        )


        report.write(
            f"Total URLs Analyzed: {total_browser_urls}\n"
        )

        report.write(
            f"Benign URLs: {benign_browser_urls}\n"
        )

        report.write(
            f"Phishing URLs: {phishing_browser_urls}\n"
        )

        report.write(
            f"Browser Risk Level: {browser_risk}\n\n"
        )


        # ----------------------------------------------------
        # PHISHING URL DETAILS
        # ----------------------------------------------------

        report.write(
            "----- DETECTED PHISHING URLs -----\n"
        )


        phishing_df = browser_df[

            browser_df["Status"]
            .astype(str)
            .str.upper()
            .eq("PHISHING")

        ]


        if phishing_df.empty:

            report.write(
                "No phishing URLs detected.\n"
            )

        else:

            for number, (_, row) in enumerate(
                phishing_df.iterrows(),
                start=1
            ):


                browser_name = row.get(
                    "Browser",
                    "Unknown"
                )


                report.write(
                    f"\n[{number}]\n"
                )

                report.write(
                    f"Browser: {browser_name}\n"
                )

                report.write(
                    f"URL: {row['URL']}\n"
                )

                report.write(
                    "Status: PHISHING\n"
                )

                report.write(
                    f"AI Confidence: {row['Confidence']}%\n"
                )


    else:

        report.write(
            "Browser analysis results were not available.\n"
        )

        report.write(
            "Run browser/suspicious_urls.py first.\n"
        )


    # ========================================================
    # AI MODEL INFORMATION
    # ========================================================

    report.write(
        "\n\n============================================================\n"
    )

    report.write(
        "                   AI MODEL ANALYSIS\n"
    )

    report.write(
        "============================================================\n\n"
    )


    report.write(
        "Browser URL Model: V3 AI Phishing URL Classifier\n"
    )

    report.write(
        "Text Features: Character-level TF-IDF\n"
    )

    report.write(
        "Structural Features: URL length, domain, path, symbols and character patterns\n"
    )

    report.write(
        "Classifier: Logistic Regression\n"
    )


    # ========================================================
    # FINAL ANALYSIS
    # ========================================================

    report.write(
        "\n\n============================================================\n"
    )

    report.write(
        "                     FINAL ANALYSIS\n"
    )

    report.write(
        "============================================================\n\n"
    )


    report.write(
        f"Email Risk Level: {email_risk}\n"
    )

    report.write(
        f"Browser Risk Level: {browser_risk}\n"
    )

    report.write(
        f"Overall Forensic Risk Level: {overall_risk}\n\n"
    )


    if overall_risk == "HIGH":

        report.write(
            "Result: High-risk indicators were detected during forensic analysis.\n"
        )

    elif overall_risk == "MEDIUM":

        report.write(
            "Result: Some suspicious browser activity was detected and should be reviewed.\n"
        )

    else:

        report.write(
            "Result: No major suspicious indicators were detected by the configured checks.\n"
        )


    report.write(
        "\n============================================================\n"
    )

    report.write(
        "                 END OF FORENSIC REPORT\n"
    )

    report.write(
        "============================================================\n"
    )


# ============================================================
# TERMINAL OUTPUT
# ============================================================

print("\n==========================================")
print("FORENSIC REPORT GENERATED SUCCESSFULLY")
print("==========================================")

print("\nEmail Risk Level:", email_risk)

print(
    "Browser Risk Level:",
    browser_risk
)

print(
    "Overall Risk Level:",
    overall_risk
)

print(
    "\nReport saved to:"
)

print(
    REPORT_FILE
)