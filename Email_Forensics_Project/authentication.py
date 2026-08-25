import email
from email import policy

# Open the email
with open("emails/sample.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

print("===== EMAIL AUTHENTICATION =====\n")

spf = msg["Received-SPF"]
dkim = msg["DKIM-Signature"]
dmarc = msg["Authentication-Results"]

print("SPF :", spf if spf else "Not Found")
print("DKIM :", "Found" if dkim else "Not Found")
print("DMARC :", dmarc if dmarc else "Not Found")