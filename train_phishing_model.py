from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from scipy.sparse import hstack
import pandas as pd
import numpy as np
import joblib
from urllib.parse import urlparse


print("======================================")
print("   V3 AI PHISHING URL MODEL")
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
# LOAD ORIGINAL DATASET
# --------------------------------------------------

print("\nLoading phishing dataset...")

dataset = load_dataset("kmack/Phishing_urls")

train_df = dataset["train"].to_pandas()
test_df = dataset["test"].to_pandas()

print("Original training samples:", len(train_df))
print("Testing samples:", len(test_df))


# --------------------------------------------------
# LOAD BENIGN DATA
# --------------------------------------------------

print("\nLoading additional benign URLs...")

benign_df = pd.read_csv(
    "dataset/benign_urls.csv"
)

benign_df = benign_df[
    ["text", "label"]
]

print(
    "Additional benign URLs:",
    len(benign_df)
)


# --------------------------------------------------
# COMBINE DATA
# --------------------------------------------------

print("\nCombining datasets...")

combined_train = pd.concat(
    [
        train_df[["text", "label"]],
        benign_df
    ],
    ignore_index=True
)

combined_train = combined_train.drop_duplicates(
    subset=["text"]
)

combined_train = combined_train.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

print(
    "Combined training samples:",
    len(combined_train)
)

print("\nLabel distribution:")
print(
    combined_train["label"].value_counts()
)


# --------------------------------------------------
# PREPARE TEXT
# --------------------------------------------------

X_train = combined_train["text"].astype(str)

y_train = combined_train["label"]

X_test = test_df["text"].astype(str)

y_test = test_df["label"]


# --------------------------------------------------
# TF-IDF FEATURES
# --------------------------------------------------

print("\nCreating character-level TF-IDF features...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=200000
)

X_train_tfidf = vectorizer.fit_transform(
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)

print("TF-IDF feature extraction completed.")


# --------------------------------------------------
# STRUCTURAL FEATURES
# --------------------------------------------------

print("\nExtracting URL structural features...")

X_train_structural = np.array(
    [
        extract_url_features(url)
        for url in X_train
    ]
)

X_test_structural = np.array(
    [
        extract_url_features(url)
        for url in X_test
    ]
)

print(
    "Structural feature extraction completed."
)


# --------------------------------------------------
# COMBINE FEATURES
# --------------------------------------------------

print("\nCombining AI features...")

X_train_final = hstack(
    [
        X_train_tfidf,
        X_train_structural
    ]
)

X_test_final = hstack(
    [
        X_test_tfidf,
        X_test_structural
    ]
)

print("Feature combination completed.")


# --------------------------------------------------
# TRAIN MODEL
# --------------------------------------------------

print("\nTraining V3 AI classifier...")

model = LogisticRegression(
    max_iter=1000
)

model.fit(
    X_train_final,
    y_train
)

print("V3 training completed.")


# --------------------------------------------------
# EVALUATION
# --------------------------------------------------

print("\nEvaluating V3 model...")

predictions = model.predict(
    X_test_final
)

accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n======================================")
print("V3 MODEL RESULTS")
print("======================================")

print(
    f"Accuracy: {accuracy * 100:.2f}%"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "BENIGN",
            "PHISHING"
        ]
    )
)


# --------------------------------------------------
# SAVE V3 MODEL
# --------------------------------------------------

joblib.dump(
    model,
    "phishing_url_model_v3.joblib"
)

joblib.dump(
    vectorizer,
    "phishing_url_vectorizer_v3.joblib"
)


print("\n======================================")
print("V3 MODEL SAVED SUCCESSFULLY")
print("======================================")

print(
    "phishing_url_model_v3.joblib"
)

print(
    "phishing_url_vectorizer_v3.joblib"
)