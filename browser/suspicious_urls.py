import pandas as pd

# Read browser history
df = pd.read_csv("history.csv")

# List of suspicious keywords
suspicious_keywords = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "paypal",
    "free",
    "gift",
    "bonus",
    ".xyz"
]

# Check for suspicious URLs
def is_suspicious(url):
    url = str(url).lower()
    return any(keyword in url for keyword in suspicious_keywords)

# Add a new column
df["Status"] = df["URL"].apply(
    lambda url: "Suspicious" if is_suspicious(url) else "Safe"
)

print(df)

# Save results
df.to_csv("suspicious_urls.csv", index=False)

print("Suspicious URL analysis completed!")