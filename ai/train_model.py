
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

DATA_PATH = os.path.join(MODEL_DIR, "processed_data.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")

if not os.path.isfile(DATA_PATH):
    raise FileNotFoundError("Run Step 2 first: processed_data.pkl not found.")

if not os.path.isfile(FEATURE_PATH):
    raise FileNotFoundError("Run Step 2 first: feature_names.pkl not found.")

X_train, X_test, y_train, y_test = joblib.load(DATA_PATH)
features = joblib.load(FEATURE_PATH)

if X_train.shape[1] != len(features):
    raise ValueError("Feature count does not match the training data.")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

print("Training Random Forest model...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n=== MODEL PERFORMANCE ===")
print(f"Accuracy : {accuracy_score(y_test, predictions) * 100:.2f}%")
print(f"Precision: {precision_score(y_test, predictions, zero_division=0) * 100:.2f}%")
print(f"Recall   : {recall_score(y_test, predictions, zero_division=0) * 100:.2f}%")
print(f"F1 Score : {f1_score(y_test, predictions, zero_division=0) * 100:.2f}%")

print("\nConfusion matrix:")
print(confusion_matrix(y_test, predictions))

print("\nClassification report:")
print(classification_report(y_test, predictions, zero_division=0))

joblib.dump(model, MODEL_PATH)

print("\nModel saved:", MODEL_PATH)
print("Model classes:", model.classes_)
print("Training completed.")
