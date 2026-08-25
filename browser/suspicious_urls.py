import pandas as pd
from transformers import pipeline


# Load pre-trained AI model
print("Loading AI phishing detection model...")

classifier = pipeline(
    "text-classification",
    model="imanoop7/bert-phishing-detector"
)


def classify_url(url):
    """Classify a URL using the AI model."""

    try:
        result = classifier(url)[0]

        label = result["label"]
        confidence = result["score"]

        # Model labels may be LABEL_0 / LABEL_1
        if label == "LABEL_1":
            status = "Suspicious"
        else:
            status = "Safe"

        return status, confidence

    except Exception as e:
        print(f"Error analyzing URL: {e}")
        return "Unknown", 0.0


# Read browser history
history_file = "history.csv"

df = pd.read_csv(history_file)

# Analyze URLs using AI
results = []

for url in df["URL"]:
    status, confidence = classify_url(str(url))

    results.append({
        "URL": url,
        "Status": status,
        "Confidence": round(confidence * 100, 2)
    })


# Create result DataFrame
result_df = pd.DataFrame(results)

print("\nAI-Based Suspicious URL Analysis:")
print(result_df)

# Save results
result_df.to_csv("suspicious_urls.csv", index=False)

print("\nAI-based suspicious URL analysis completed!")
print("Results saved to suspicious_urls.csv")