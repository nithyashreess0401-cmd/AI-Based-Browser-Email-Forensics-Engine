import email
from email import policy
import re
from urllib.parse import urlparse

# Open the email
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

print("===== LINK ANALYSIS =====\n")

if not urls:
    print("No URLs found.")

else:
    for url in urls:
        print("URL:", url)

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        suspicious = False
        reasons = []

        # Check for IP address instead of domain name
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            suspicious = True
            reasons.append("Uses an IP address")

        # Check for suspicious URL patterns
        if "@" in url:
            suspicious = True
            reasons.append("Contains @ symbol")

        if len(url) > 150:
            suspicious = True
            reasons.append("Unusually long URL")

        # Check for suspicious words
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
                reasons.append("Contains suspicious keyword")
                break

        if suspicious:
            print("WARNING: Suspicious Link Detected")
            print("Reasons:")
            for reason in reasons:
                print("-", reason)
        else:
            print("No obvious suspicious pattern detected")

        print()