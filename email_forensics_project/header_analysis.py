
import email
import os
import sys
from email import policy

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_PATH = os.path.join(
    BASE_DIR, "emails", "gmail_message.eml"
)

# Allow the email file to be supplied as a command-line argument.
if len(sys.argv) > 1:
    EMAIL_PATH = os.path.abspath(sys.argv[1])

print("===== EMAIL HEADER ANALYSIS =====")

if not os.path.isfile(EMAIL_PATH):
    print(f"ERROR: Email file not found: {EMAIL_PATH}")
    print(
        "Please upload or place a valid .eml file at "
        f"{os.path.join(BASE_DIR, 'emails', 'gmail_message.eml')}"
    )
    sys.exit(1)

with open(EMAIL_PATH, "rb") as file:
    msg = email.message_from_binary_file(
        file, policy=policy.default
    )

print("\nFrom       :", msg.get("From", "Not available"))
print("To         :", msg.get("To", "Not available"))
print("Reply-To   :", msg.get("Reply-To", "Not available"))
print("Subject    :", msg.get("Subject", "Not available"))
print("Date       :", msg.get("Date", "Not available"))
print("Message-ID :", msg.get("Message-ID", "Not available"))
print("Content-Type:", msg.get("Content-Type", "Not available"))

print("\nEmail header analysis completed.")
