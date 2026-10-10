
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

dataset_path = os.path.join(BASE_DIR, "dataset", "phishing_url_dataset.csv")
output_path = os.path.join(BASE_DIR, "dataset", "cleaned_dataset.csv")

FEATURES = [
    "url_length", "valid_url", "at_symbol",
    "sensitive_words_count", "path_length", "isHttps",
    "nb_dots", "nb_hyphens", "nb_and", "nb_or",
    "nb_www", "nb_com", "nb_underscore"
]

if not os.path.isfile(dataset_path):
    raise FileNotFoundError(f"Dataset not found: {dataset_path}")

df = pd.read_csv(dataset_path)
df.columns = df.columns.str.strip()

required = FEATURES + ["target"]
missing = [col for col in required if col not in df.columns]

if missing:
    raise ValueError(
        f"Missing required columns: {missing}\n"
        f"Actual columns: {df.columns.tolist()}"
    )

df = df[required].copy()

for col in required:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df = df.dropna().drop_duplicates()

if df.empty:
    raise ValueError("No valid rows remain after cleaning.")

if not set(df["target"].unique()).issubset({0, 1}):
    raise ValueError("target must contain only 0 and 1.")

if df["target"].nunique() != 2:
    raise ValueError("Dataset must contain both target classes: 0 and 1.")

os.makedirs(os.path.dirname(output_path), exist_ok=True)
df.to_csv(output_path, index=False)

print("Dataset preprocessing completed.")
print("Cleaned shape:", df.shape)
print("Target counts:")
print(df["target"].value_counts().sort_index())
print("Saved to:", output_path)
