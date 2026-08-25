import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

print("=" * 60)
print("STEP 2 - FEATURE PREPARATION")
print("=" * 60)

# Load cleaned dataset
df = pd.read_csv("dataset/cleaned_dataset.csv")

# Separate features and target
X = df.drop("target", axis=1)
y = df["target"]

print("\nFeatures:")
print(X.columns.tolist())

print("\nTarget:")
print("target")

# Split data into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))

# Scale numerical features
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Create models folder
os.makedirs("models", exist_ok=True)

# Save scaler
joblib.dump(scaler, "models/scaler.pkl")

# Save processed data
joblib.dump(
    (X_train_scaled, X_test_scaled, y_train, y_test),
    "models/processed_data.pkl"
)

print("\nSaved:")
print("✓ models/scaler.pkl")
print("✓ models/processed_data.pkl")

print("\nSTEP 2 COMPLETED!")