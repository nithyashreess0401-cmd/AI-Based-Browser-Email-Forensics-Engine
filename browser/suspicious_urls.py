import pandas as pd
import joblib
import numpy as np
import os
from scipy.sparse import hstack
from urllib.parse import urlparse


print("======================================")
print("   AI PHISHING URL ANALYSIS - V3")
print("======================================")


# --------------------------------------------------
# URL STRUCTURAL FEATURES
# --------------------------------------------------

def extract_url_features(url):

    url = str(url)

    try:

        parsed = urlparse(url)

        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        features = [
            len(url),
            len(domain),
            len(path),
            len(query),

            domain.count("."),
            domain.count("-"),
            domain.count("_"),

            url.count("/"),
            url.count("?"),
            url.count("="),
            url.count("&"),
            url.count("%"),

            sum(c.isdigit() for c in url),
            sum(c.isalpha() for c in url),

            int(url.startswith("https://")),
            int(url.startswith("http://")),

            int("@" in url),
            int("://" in url),

            len(set(domain))
        ]

        return features

    except Exception:

        return [0] * 19


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_url_model_v3.joblib"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_url_vectorizer_v3.joblib"
)

HISTORY_PATH = os.path.join(
    BASE_DIR,
    "history.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "suspicious_urls_v3.csv"
)


# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

print("\nLoading V3 AI phishing model...")

if not os.path.exists(MODEL_PATH):

    print("\nERROR: V3 model not found.")
    print(MODEL_PATH)
    print("\nRun train_phishing_model.py first.")
    exit()

if not os.path.exists(VECTORIZER_PATH):

    print("\nERROR: V3 vectorizer not found.")
    print(VECTORIZER_PATH)
    print("\nRun train_phishing_model.py first.")
    exit()


model = joblib.load(MODEL_PATH)

vectorizer = joblib.load(VECTORIZER_PATH)

print("V3 AI model loaded successfully!")


# --------------------------------------------------
# LOAD BROWSER HISTORY
# --------------------------------------------------

print("\nLoading browser history...")

if not os.path.exists(HISTORY_PATH):

    print("\nERROR: history.csv not found.")
    print(HISTORY_PATH)
    exit()


df = pd.read_csv(HISTORY_PATH)


# --------------------------------------------------
# CHECK URL COLUMN
# --------------------------------------------------

if "URL" not in df.columns:

    print("\nERROR: URL column not found in history.csv")

    print("\nAvailable columns:")

    print(df.columns.tolist())

    exit()


df = df.dropna(
    subset=["URL"]
)

df["URL"] = df["URL"].astype(str)


# --------------------------------------------------
# REMOVE DUPLICATES
# --------------------------------------------------

urls = (
    df["URL"]
    .drop_duplicates()
    .tolist()
)

print(
    f"\nTotal unique URLs to analyze: {len(urls)}"
)

if len(urls) == 0:

    print("\nNo URLs found.")

    exit()


# --------------------------------------------------
# TF-IDF FEATURES
# --------------------------------------------------

print("\nCreating TF-IDF features...")

url_tfidf = vectorizer.transform(
    urls
)


# --------------------------------------------------
# STRUCTURAL FEATURES
# --------------------------------------------------

print("Creating structural URL features...")

url_structural = np.array(
    [
        extract_url_features(url)
        for url in urls
    ]
)


# --------------------------------------------------
# COMBINE FEATURES
# --------------------------------------------------

print("Combining AI features...")

url_features = hstack(
    [
        url_tfidf,
        url_structural
    ]
)


# --------------------------------------------------
# PREDICTION
# --------------------------------------------------

print("Running AI predictions...")

predictions = model.predict(
    url_features
)

probabilities = model.predict_proba(
    url_features
)


# --------------------------------------------------
# CREATE RESULTS
# --------------------------------------------------

results = []

for url, prediction, probability in zip(
    urls,
    predictions,
    probabilities
):

    if prediction == 1:

        status = "PHISHING"
        confidence = probability[1]

    else:

        status = "BENIGN"
        confidence = probability[0]


    # Browser name
    if "Browser" in df.columns:

        browsers = (
            df[df["URL"] == url]["Browser"]
            .dropna()
            .unique()
            .tolist()
        )

        browser_name = ", ".join(browsers)

    else:

        browser_name = "Unknown"


    results.append({

        "Browser": browser_name,

        "URL": url,

        "Status": status,

        "Confidence": round(
            confidence * 100,
            2
        )

    })


# --------------------------------------------------
# CREATE DATAFRAME
# --------------------------------------------------

result_df = pd.DataFrame(
    results
)


# --------------------------------------------------
# SAVE RESULTS
# --------------------------------------------------

result_df.to_csv(
    OUTPUT_PATH,
    index=False
)


# --------------------------------------------------
# DISPLAY RESULTS
# --------------------------------------------------

print("\n======================================")
print("V3 AI PHISHING URL ANALYSIS")
print("======================================")

if len(result_df) > 0:

    print(
        result_df.head(20).to_string(
            index=False
        )
    )


# --------------------------------------------------
# SUMMARY
# --------------------------------------------------

total = len(result_df)

benign = sum(
    result_df["Status"] == "BENIGN"
)

phishing = sum(
    result_df["Status"] == "PHISHING"
)


print("\n======================================")
print("V3 ANALYSIS SUMMARY")
print("======================================")

print(
    f"Total URLs analyzed: {total}"
)

print(
    f"Benign URLs: {benign}"
)

print(
    f"Phishing URLs: {phishing}"
)


# --------------------------------------------------
# RISK LEVEL
# --------------------------------------------------

if phishing == 0:

    risk_level = "LOW"

elif phishing <= 3:

    risk_level = "MEDIUM"

else:

    risk_level = "HIGH"


print(
    f"Overall Browser Risk Level: {risk_level}"
)


# --------------------------------------------------
# FINISH
# --------------------------------------------------

print("\n======================================")
print("BROWSER ANALYSIS COMPLETED")
print("======================================")

print(
    "\nResults saved to:"
)

print(
    OUTPUT_PATH
)