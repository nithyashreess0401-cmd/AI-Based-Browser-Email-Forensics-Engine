import pandas as pd
import os

print("=" * 60)
print("AI-BASED BROWSER AND EMAIL FORENSICS ENGINE")
print("STEP 1 - DATA PREPROCESSING")
print("=" * 60)

# Load dataset
dataset_path = "dataset/phishing_url_dataset.csv"

if not os.path.exists(dataset_path):
    print("\nERROR: Dataset not found!")
    print("Expected:", dataset_path)
    exit()

df = pd.read_csv(dataset_path)

print("\nDataset loaded successfully!")
print("Original shape:", df.shape)

# Remove duplicate records
duplicate_count = df.duplicated().sum()
print("Duplicate records:", duplicate_count)

df = df.drop_duplicates()

# Check missing values
print("\nMissing values:")
print(df.isnull().sum())

# Remove missing rows
df = df.dropna()

print("\nFinal shape:", df.shape)

# Display columns
print("\nDataset columns:")
for column in df.columns:
    print("-", column)

# Save cleaned dataset
output_path = "dataset/cleaned_dataset.csv"
df.to_csv(output_path, index=False)

print("\nCleaned dataset saved to:")
print(output_path)

print("\nSTEP 1 COMPLETED!")