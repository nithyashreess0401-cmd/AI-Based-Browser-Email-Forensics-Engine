
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "dataset", "cleaned_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")

FEATURES = [
    "url_length", "valid_url", "at_symbol",
    "sensitive_words_count", "path_length", "isHttps",
    "nb_dots", "nb_hyphens", "nb_and", "nb_or",
    "nb_www", "nb_com", "nb_underscore"
]

if not os.path.isfile(DATA_PATH):
    raise FileNotFoundError("Run Step 1 first: cleaned_dataset.csv not found.")

df = pd.read_csv(DATA_PATH)

missing = [c for c in FEATURES + ["target"] if c not in df.columns]
if missing:
    raise ValueError(f"Missing dataset columns: {missing}")

X = df[FEATURES].astype(float)
y = df["target"].astype(int)

if y.nunique() != 2:
    raise ValueError("Dataset must contain both classes: 0 and 1.")

if y.value_counts().min() < 2:
    raise ValueError("Each target class needs at least two records for splitting.")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
joblib.dump(
    (X_train_scaled, X_test_scaled, y_train, y_test),
    os.path.join(MODEL_DIR, "processed_data.pkl")
)
joblib.dump(FEATURES, os.path.join(MODEL_DIR, "feature_names.pkl"))

print("Feature preparation completed.")
print("Features:", FEATURES)
print("Training rows:", len(X_train))
print("Testing rows:", len(X_test))
print("Saved scaler.pkl, processed_data.pkl and feature_names.pkl.")
