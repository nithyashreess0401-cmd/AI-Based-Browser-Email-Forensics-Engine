import os
import pandas as pd
import joblib
import numpy as np
import os
from scipy.sparse import hstack
from urllib.parse import urlparse



print("======================================")
print("   AI PHISHING URL ANALYSIS - V3")
print("======================================")


<<<<<<< HEAD
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
=======
# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "phishing_url_model_v2.joblib"
>>>>>>> 99d42bb (Update browser forensic phishing analysis)
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
<<<<<<< HEAD
    "models",
    "phishing_url_vectorizer_v3.joblib"
)

HISTORY_PATH = os.path.join(
=======
    "phishing_url_vectorizer_v2.joblib"
)

HISTORY_FILE = os.path.join(
>>>>>>> 99d42bb (Update browser forensic phishing analysis)
    BASE_DIR,
    "history.csv"
)

<<<<<<< HEAD
OUTPUT_PATH = os.path.join(
=======
OUTPUT_FILE = os.path.join(
>>>>>>> 99d42bb (Update browser forensic phishing analysis)
    BASE_DIR,
    "suspicious_urls_v3.csv"
)


<<<<<<< HEAD
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

=======
# ==========================================================
# CHECK FILES
# ==========================================================

if not os.path.exists(MODEL_PATH):
    print("ERROR: AI model not found:")
    print(MODEL_PATH)
    raise SystemExit(1)

if not os.path.exists(VECTORIZER_PATH):
    print("ERROR: AI vectorizer not found:")
    print(VECTORIZER_PATH)
    raise SystemExit(1)

if not os.path.exists(HISTORY_FILE):
    print("ERROR: history.csv not found:")
    print(HISTORY_FILE)
    raise SystemExit(1)


# ==========================================================
# LOAD AI MODEL
# ==========================================================

print("\nLoading AI phishing model...")

model = joblib.load(
    MODEL_PATH
)

vectorizer = joblib.load(
    VECTORIZER_PATH
)

print("AI model loaded successfully.")


# ==========================================================
# LOAD HISTORY
# ==========================================================

print("\nLoading browser history...")

df = pd.read_csv(
    HISTORY_FILE
)

if "URL" not in df.columns:
    print("ERROR: URL column not found in history.csv")
    raise SystemExit(1)
>>>>>>> 99d42bb (Update browser forensic phishing analysis)

df = df.dropna(
    subset=["URL"]
)

df["URL"] = df["URL"].astype(str)

<<<<<<< HEAD

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
=======
# Remove empty URLs
df = df[
    df["URL"].str.strip() != ""
]


# ==========================================================
# REMOVE DUPLICATE URLS
# ==========================================================

unique_urls = (
    df["URL"]
    .drop_duplicates()
    .tolist()
)

print(
    f"\nTotal unique URLs: {len(unique_urls)}"
)


if not unique_urls:

    print("No URLs available for analysis.")

    empty_df = pd.DataFrame(
        columns=[
            "Browser",
            "URL",
            "Status",
            "Confidence"
        ]
    )

    empty_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    raise SystemExit(0)


# ==========================================================
# AI FEATURE EXTRACTION
# ==========================================================

print(
    "\nStarting AI phishing analysis..."
)

url_features = vectorizer.transform(
    unique_urls
)


# ==========================================================
# PREDICTION
# ==========================================================
>>>>>>> 99d42bb (Update browser forensic phishing analysis)

predictions = model.predict(
    url_features
)

probabilities = model.predict_proba(
    url_features
)


<<<<<<< HEAD
# --------------------------------------------------
# CREATE RESULTS
# --------------------------------------------------
=======
# ==========================================================
# BUILD RESULTS
# ==========================================================
>>>>>>> 99d42bb (Update browser forensic phishing analysis)

results = []


for url, prediction, probability in zip(
    unique_urls,
    predictions,
    probabilities
):

    if prediction == 1:

        status = "PHISHING"
        confidence = probability[1]

    else:

        status = "BENIGN"
        confidence = probability[0]


<<<<<<< HEAD
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
=======
    matching_rows = df[
        df["URL"] == url
    ]


    browsers = (
        matching_rows["Browser"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
        if "Browser" in matching_rows.columns
        else []
    )


    visit_times = (
        matching_rows["Visit Time"]
        .dropna()
        .astype(str)
        .tolist()
        if "Visit Time" in matching_rows.columns
        else []
    )


    results.append(
        {
            "Browser": ", ".join(
                browsers
            ),

            "URL": url,

            "Status": status,

            "Confidence": round(
                confidence * 100,
                2
            ),

            "Visit Time": (
                visit_times[0]
                if visit_times
                else ""
            )
        }
    )


# ==========================================================
# SAVE RESULTS
# ==========================================================

result_df = pd.DataFrame(
    results
)

result_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ==========================================================
# SUMMARY
# ==========================================================

total = len(
    result_df
>>>>>>> 99d42bb (Update browser forensic phishing analysis)
)

phishing = int(
    (
        result_df["Status"]
        == "PHISHING"
    ).sum()
)

<<<<<<< HEAD

print("\n======================================")
print("V3 ANALYSIS SUMMARY")
print("======================================")

print(
    f"Total URLs analyzed: {total}"
)

print(
    f"Benign URLs: {benign}"
=======
benign = int(
    (
        result_df["Status"]
        == "BENIGN"
    ).sum()
)


print("\n======================================")
print("       AI ANALYSIS SUMMARY")
print("======================================")

print(
    f"Total URLs: {total}"
>>>>>>> 99d42bb (Update browser forensic phishing analysis)
)

print(
    f"Phishing URLs: {phishing}"
)

<<<<<<< HEAD

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
=======
print(
    f"Benign URLs: {benign}"
)

print(
    f"\nResults saved to:"
)

print(
    OUTPUT_FILE
)

print(
    "\nAI phishing analysis completed!"
>>>>>>> 99d42bb (Update browser forensic phishing analysis)
)