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

print("===== LINK ANALYSIS =====\n")

if not urls:
    print("No URLs found.")
else:
    for url in urls:
        print("URL:", url)

        if "paypal-login-security" in url:
            print("⚠️ Suspicious Link Detected!\n")
        else:
            print("✅ Safe Link\n")