import joblib
import pandas as pd
import os

print("=" * 60)
print("AI-BASED BROWSER AND EMAIL FORENSICS ENGINE")
print("STEP 4 - AI PREDICTION")
print("=" * 60)

# --------------------------------------------------
# Load trained AI model
# --------------------------------------------------

model_path = "models/phishing_model.pkl"
scaler_path = "models/scaler.pkl"

if not os.path.exists(model_path):
    print("\nERROR: Trained model not found!")
    print("Run Step 3 first.")
    exit()

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

print("\nAI model loaded successfully!")


# --------------------------------------------------
# New evidence
# --------------------------------------------------
# This is temporary test data.
# Later, Member 1/2 will provide these values.

sample = {
    "url_length": 54,
    "valid_url": 1,
    "at_symbol": 0,
    "sensitive_words_count": 2,
    "path_length": 15,
    "isHttps": 1,
    "nb_dots": 2,
    "nb_hyphens": 1,
    "nb_and": 0,
    "nb_or": 0,
    "nb_www": 1,
    "nb_com": 1,
    "nb_underscore": 0
}


# --------------------------------------------------
# Convert input into DataFrame
# --------------------------------------------------

input_data = pd.DataFrame([sample])

print("\nNew evidence received.")

# Make sure feature order is correct
feature_order = [
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

input_data = input_data[feature_order]


# --------------------------------------------------
# Apply same scaling used during training
# --------------------------------------------------

input_scaled = scaler.transform(input_data)


# --------------------------------------------------
# AI Prediction
# --------------------------------------------------

prediction = model.predict(input_scaled)[0]

probabilities = model.predict_proba(input_scaled)[0]

safe_probability = probabilities[0]
phishing_probability = probabilities[1]

confidence = max(probabilities) * 100


# --------------------------------------------------
# Display result
# --------------------------------------------------

print("\n" + "=" * 60)
print("AI INVESTIGATION RESULT")
print("=" * 60)

if prediction == 1:
    result = "PHISHING"
else:
    result = "LEGITIMATE"

print(f"\nPrediction          : {result}")
print(f"Confidence          : {confidence:.2f}%")
print(f"Legitimate Probability : {safe_probability * 100:.2f}%")
print(f"Phishing Probability   : {phishing_probability * 100:.2f}%")

print("\nSTEP 4 COMPLETED!")