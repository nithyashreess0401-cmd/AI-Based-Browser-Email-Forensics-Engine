import os
import joblib
import pandas as pd
from urllib.parse import urlparse

# --------------------------------------------------
# PATHS
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

MODEL_PATH = os.path.join(PROJECT_DIR, "models", "phishing_model.pkl")
SCALER_PATH = os.path.join(PROJECT_DIR, "models", "scaler.pkl")
HISTORY_PATH = os.path.join(BASE_DIR, "history.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "suspicious_urls_v3.csv")

FEATURES = [
    "url_length",
    "valid_url",
    "at_symbol",
    "sensitive_words_count",
    "path_length",
    "isHttps",
    "nb_dots",
    "nb_hyphens",
    "nb_and",
    "nb_or",
    "nb_www",
    "nb_com",
    "nb_underscore",
]

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "signin", "banking", "confirm", "wallet",
    "payment", "authenticate", "suspend"
]


# --------------------------------------------------
# URL FEATURE EXTRACTION
# Must match the features used to train the AI model
# --------------------------------------------------
def extract_features(url):
    url = str(url).strip()
    lower_url = url.lower()

    parsed = urlparse(
        url if "://" in url else "//" + url
    )

    domain = parsed.netloc.split("@")[-1].split(":")[0]

    return {
        "url_length": len(url),
        "valid_url": int(bool(domain and "." in domain)),
        "at_symbol": int("@" in url),
        "sensitive_words_count": sum(
            lower_url.count(word) for word in SUSPICIOUS_WORDS
        ),
        "path_length": len(parsed.path),
        "isHttps": int(lower_url.startswith("https://")),
        "nb_dots": lower_url.count("."),
        "nb_hyphens": lower_url.count("-"),
        "nb_and": lower_url.count("and"),
        "nb_or": lower_url.count("or"),
        "nb_www": lower_url.count("www"),
        "nb_com": lower_url.count(".com"),
        "nb_underscore": lower_url.count("_"),
    }


def main():
    print("=== AI BROWSER PHISHING ANALYSIS ===")

    for path in [MODEL_PATH, SCALER_PATH, HISTORY_PATH]:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Required file not found: {path}")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    if len(FEATURES) != getattr(model, "n_features_in_", len(FEATURES)):
        raise ValueError("AI model expects a different number of features.")

    if len(FEATURES) != getattr(scaler, "n_features_in_", len(FEATURES)):
        raise ValueError("Scaler expects a different number of features.")

    history = pd.read_csv(HISTORY_PATH)

    if "URL" not in history.columns:
        raise ValueError(
            f"history.csv needs a 'URL' column. Found: {history.columns.tolist()}"
        )

    history = history.dropna(subset=["URL"]).copy()
    history["URL"] = history["URL"].astype(str).str.strip()
    history = history[history["URL"] != ""]

    unique_urls = history["URL"].drop_duplicates().tolist()

    if not unique_urls:
        raise ValueError("No URLs found in browser history.")

    feature_df = pd.DataFrame(
        [extract_features(url) for url in unique_urls],
        columns=FEATURES
    )

    scaled_features = scaler.transform(feature_df)
    predictions = model.predict(scaled_features)
    probabilities = model.predict_proba(scaled_features)
    classes = list(model.classes_)

    # Identify the phishing class from the model's actual labels.
    phishing_class = next(
        (
            c for c in classes
            if str(c).strip().lower() in
            {"1", "phishing", "malicious", "unsafe"}
        ),
        None
    )

    if phishing_class is None:
        raise ValueError(
            f"Cannot identify phishing label from model classes: {classes}. "
            "Check the target labels used during training."
        )

    phishing_index = classes.index(phishing_class)
    results = []

    for url, prediction, probs in zip(
        unique_urls, predictions, probabilities
    ):
        matching = history[history["URL"] == url]

        browser_names = (
            matching["Browser"].dropna().astype(str).unique().tolist()
            if "Browser" in matching.columns else []
        )

        visit_times = (
            matching["Visit Time"].dropna().astype(str).tolist()
            if "Visit Time" in matching.columns else []
        )

        status = (
            "PHISHING" if prediction == phishing_class else "BENIGN"
        )

        predicted_index = classes.index(prediction)

        results.append({
            "Browser": ", ".join(browser_names) or "Unknown",
            "URL": url,
            "Status": status,
            "Confidence": round(float(probs[predicted_index]) * 100, 2),
            "Phishing Probability": round(
                float(probs[phishing_index]) * 100, 2
            ),
            "Visit Time": visit_times[0] if visit_times else ""
        })

    result_df = pd.DataFrame(results)
    result_df.to_csv(OUTPUT_PATH, index=False)

    print(f"URLs analyzed: {len(result_df)}")
    print(f"Phishing URLs: {(result_df['Status'] == 'PHISHING').sum()}")
    print(f"Benign URLs: {(result_df['Status'] == 'BENIGN').sum()}")
    print(f"Results saved to: {OUTPUT_PATH}")
    print("Browser AI analysis completed.")


if __name__ == "__main__":
    main()
