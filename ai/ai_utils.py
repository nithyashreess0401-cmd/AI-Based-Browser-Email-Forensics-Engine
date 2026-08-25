import os
import joblib
import pandas as pd

# ---------------------------------------
# File paths
# ---------------------------------------

MODEL_PATH = "models/phishing_model.pkl"
SCALER_PATH = "models/scaler.pkl"


# ---------------------------------------
# Feature order
# Must be exactly the same as training
# ---------------------------------------

FEATURE_ORDER = [
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


# ---------------------------------------
# Load AI model
# ---------------------------------------

def load_ai_model():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "AI model not found. Run train_model.py first."
        )

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            "Scaler not found. Run feature_extraction.py first."
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    return model, scaler


# ---------------------------------------
# Analyze evidence
# ---------------------------------------

def analyze_url(features):

    # Load trained AI
    model, scaler = load_ai_model()

    # Convert input into DataFrame
    input_data = pd.DataFrame([features])

    # Ensure correct feature order
    input_data = input_data[FEATURE_ORDER]

    # Apply same scaling used during training
    input_scaled = scaler.transform(input_data)

    # AI prediction
    prediction = model.predict(input_scaled)[0]

    # AI probabilities
    probabilities = model.predict_proba(input_scaled)[0]

    legitimate_probability = probabilities[0]
    phishing_probability = probabilities[1]

    # Confidence
    confidence = max(probabilities)

    # Risk score
    risk_score = phishing_probability * 100

    # Risk level
    if risk_score >= 70:
        risk_level = "HIGH"

    elif risk_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # Final result
    if prediction == 1:
        result = "PHISHING"
    else:
        result = "LEGITIMATE"

    return {
        "prediction": result,
        "confidence": round(confidence * 100, 2),
        "legitimate_probability": round(
            legitimate_probability * 100, 2
        ),
        "phishing_probability": round(
            phishing_probability * 100, 2
        ),
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level
    }


# ---------------------------------------
# Test AI module
# ---------------------------------------

if __name__ == "__main__":

    sample_features = {
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

    result = analyze_url(sample_features)

    print("=" * 60)
    print("AI UTILS TEST")
    print("=" * 60)

    print("\nAI Investigation Result")

    for key, value in result.items():
        print(f"{key}: {value}")