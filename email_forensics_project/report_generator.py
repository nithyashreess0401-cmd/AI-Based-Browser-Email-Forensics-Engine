import email
from email import policy
import re
from urllib.parse import urlparse

# Open Gmail email
with open("emails/gmail_message.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

# Get email body
if msg.is_multipart():
    body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body += part.get_content()
else:
    body = msg.get_content()

# Extract URLs
urls = re.findall(r'https?://[^\s<>"\']+', body)

# Create report
with open("reports/forensic_report.txt", "w", encoding="utf-8") as report:

    report.write("========== EMAIL FORENSIC REPORT ==========\n\n")

    report.write("----- EMAIL DETAILS -----\n")
    report.write(f"From: {msg['From']}\n")
    report.write(f"To: {msg['To']}\n")
    report.write(f"Reply-To: {msg['Reply-To']}\n")
    report.write(f"Subject: {msg['Subject']}\n")
    report.write(f"Date: {msg['Date']}\n")
    report.write(f"Message-ID: {msg['Message-ID']}\n\n")

    # Authentication
    report.write("----- AUTHENTICATION -----\n")

    spf = msg["Received-SPF"]
    dkim = msg["DKIM-Signature"]
    dmarc = msg["Authentication-Results"]

    report.write(f"SPF: {spf if spf else 'Not Found'}\n")
    report.write(f"DKIM: {'Found' if dkim else 'Not Found'}\n")
    report.write(f"DMARC: {dmarc if dmarc else 'Not Found'}\n\n")

    # URL analysis
    report.write("----- URL ANALYSIS -----\n")

    suspicious_count = 0

    if not urls:
        report.write("No URLs Found\n")
    else:
        for url in urls:

            report.write(f"\nURL: {url}\n")

            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            suspicious = False
            reasons = []

            # IP address check
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
                suspicious = True
                reasons.append("Uses an IP address")

            # @ symbol check
            if "@" in url:
                suspicious = True
                reasons.append("Contains @ symbol")

            # Long URL check
            if len(url) > 150:
                suspicious = True
                reasons.append("Unusually long URL")

            # Suspicious keyword check
            suspicious_words = [
                "login",
                "verify",
                "password",
                "urgent",
                "confirm"
            ]

            for word in suspicious_words:
                if word in url.lower():
                    suspicious = True
                    reasons.append("Contains suspicious keyword")
                    break

            if suspicious:
                suspicious_count += 1
                report.write("Status: SUSPICIOUS\n")
                report.write("Reasons:\n")

                for reason in reasons:
                    report.write(f"- {reason}\n")

            else:
                report.write("Status: No obvious suspicious pattern detected\n")

    # Final analysis
    report.write("\n----- FINAL ANALYSIS -----\n")

    if suspicious_count > 0:
        report.write("Risk Level: HIGH\n")
        report.write("Suspicious links were detected in the email.\n")
    elif urls:
        report.write("Risk Level: LOW\n")
        report.write("URLs were found, but no obvious suspicious URL pattern was detected.\n")
    else:
        report.write("Risk Level: LOW\n")
        report.write("No URLs were found in the email.\n")

print("Forensic report generated successfully!")