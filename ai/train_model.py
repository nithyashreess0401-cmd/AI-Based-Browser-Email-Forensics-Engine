import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import os

print("=" * 60)
print("AI-BASED BROWSER AND EMAIL FORENSICS ENGINE")
print("STEP 3 - AI MODEL TRAINING")
print("=" * 60)

# Load processed data
data = joblib.load("models/processed_data.pkl")

X_train, X_test, y_train, y_test = data

print("\nProcessed data loaded successfully!")

print("Training samples:", len(X_train))
print("Testing samples :", len(X_test))

# Create Random Forest AI model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

print("\nTraining Random Forest model...")

# Train the model
model.fit(X_train, y_train)

print("Model training completed!")

# Make predictions on test data
y_pred = model.predict(X_test)

# Calculate evaluation metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)

print("\n" + "=" * 60)
print("MODEL PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1 Score  : {f1 * 100:.2f}%")

# Confusion matrix
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Classification report
print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    zero_division=0
))

# Feature importance
feature_names = [
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
    "nb_underscore"
]

print("\nFeature Importance:")
print("-" * 40)

importance = model.feature_importances_

for name, value in sorted(
    zip(feature_names, importance),
    key=lambda x: x[1],
    reverse=True
):
    print(f"{name:<25} {value:.4f}")

# Create models folder
os.makedirs("models", exist_ok=True)

# Save trained model
model_path = "models/phishing_model.pkl"

joblib.dump(model, model_path)

print("\n" + "=" * 60)
print("MODEL SAVED SUCCESSFULLY!")
print("=" * 60)

print("\nLocation:")
print(model_path)

print("\nSTEP 3 COMPLETED!")