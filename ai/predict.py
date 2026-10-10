```python
import joblib
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "phishing_model.pkl"
SCALER_PATH = ROOT / "models" / "scaler.pkl"
FEATURES_PATH = ROOT / "models" / "feature_names.pkl"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
features = joblib.load(FEATURES_PATH)

print("AI-Based Phishing URL Prediction")

url = input("Enter URL: ").strip()

if not url:
    print("Please enter a valid URL.")
    raise SystemExit

from urllib.parse import urlparse
import re

parsed = urlparse(url if "://" in url else "https://" + url)
domain = parsed.netloc
path = parsed.path

suspicious_words = [
    "login", "verify", "update", "secure",
    "account", "bank", "password", "confirm"
]

data = {
    "url_length": len(url),
    "valid_url": int(bool(domain and "." in domain)),
    "at_symbol": int("@" in url),
    "sensitive_words_count": sum(
        word in url.lower() for word in suspicious_words
    ),
    "path_length": len(path),
    "isHttps": int(url.lower().startswith("https://")),
    "nb_dots": url.count("."),
    "nb_hyphens": url.count("-"),
    "nb_and": url.count("&"),
    "nb_or": url.count("|"),
    "nb_www": url.lower().count("www"),
    "nb_com": url.lower().count(".com"),
    "nb_underscore": url.count("_"),
}

X = pd.DataFrame([[data[name] for name in features]], columns=features)
X_scaled = scaler.transform(X)

prediction = model.predict(X_scaled)[0]

print("Model prediction:", prediction)
print("⚠️ Verify the target-label mapping before interpreting this as phishing or legitimate.")
```
