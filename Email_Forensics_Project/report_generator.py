import email
from email import policy
import re

# Open the email
with open("emails/sample.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

# Read email body
if msg.is_multipart():
    body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body += part.get_content()
else:
    body = msg.get_content()

# Extract URLs
urls = re.findall(r'https?://[^\s]+', body)

# Create Report
with open("reports/forensic_report.txt", "w") as report:

    report.write("========== EMAIL FORENSIC REPORT ==========\n\n")

    report.write(f"From: {msg['From']}\n")
    report.write(f"To: {msg['To']}\n")
    report.write(f"Subject: {msg['Subject']}\n")
    report.write(f"Date: {msg['Date']}\n\n")

    report.write("----- Authentication -----\n")
    report.write(f"SPF: {msg['Received-SPF'] if msg['Received-SPF'] else 'Not Found'}\n")
    report.write(f"DKIM: {'Found' if msg['DKIM-Signature'] else 'Not Found'}\n")
    report.write(f"DMARC: {msg['Authentication-Results'] if msg['Authentication-Results'] else 'Not Found'}\n\n")

    report.write("----- URLs -----\n")

    if urls:
        for url in urls:
            report.write(url + "\n")
    else:
        report.write("No URLs Found\n")

    report.write("\n----- Final Analysis -----\n")

    if urls:
        report.write("Suspicious Email (Contains URL)\n")
    else:
        report.write("Safe Email\n")

print("Forensic Report Generated Successfully!")