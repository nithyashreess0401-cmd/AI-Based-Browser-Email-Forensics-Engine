import pandas as pd
import joblib

print("======================================")
print("   AI PHISHING URL ANALYSIS - V2")
print("======================================")

# Load improved AI model
print("\nLoading improved AI phishing model...")

model = joblib.load("phishing_url_model_v2.joblib")
vectorizer = joblib.load("phishing_url_vectorizer_v2.joblib")

print("V2 AI model loaded successfully!")

# Load browser history
history_file = "history.csv"
df = pd.read_csv(history_file)

df = df.dropna(subset=["URL"])
df["URL"] = df["URL"].astype(str)

# Remove duplicate URLs
urls = df["URL"].drop_duplicates().tolist()

print(f"\nTotal unique URLs to analyze: {len(urls)}")
print("Starting V2 AI phishing analysis...\n")

# Convert URLs into TF-IDF features
url_features = vectorizer.transform(urls)

# Predict
predictions = model.predict(url_features)
probabilities = model.predict_proba(url_features)

results = []

for url, prediction, probability in zip(
    urls,
    predictions,
    probabilities
):

    if prediction == 1:
        status = "PHISHING"
        confidence = probability[1]
    else:
        status = "BENIGN"
        confidence = probability[0]

    browsers = df[
        df["URL"] == url
    ]["Browser"].dropna().unique().tolist()

    results.append({
        "Browser": ", ".join(browsers),
        "URL": url,
        "Status": status,
        "Confidence": round(confidence * 100, 2)
    })

# Create result DataFrame
result_df = pd.DataFrame(results)

# Save V2 results
result_df.to_csv(
    "suspicious_urls_v2.csv",
    index=False
)

# Display results
print("\n======================================")
print("V2 AI PHISHING URL ANALYSIS")
print("======================================")

print(result_df.head(20))

# Summary
total = len(result_df)

benign = sum(
    result_df["Status"] == "BENIGN"
)

phishing = sum(
    result_df["Status"] == "PHISHING"
)

print("\n======================================")
print("V2 ANALYSIS SUMMARY")
print("======================================")

print(f"Total URLs analyzed: {total}")
print(f"Benign URLs: {benign}")
print(f"Phishing URLs: {phishing}")

print("\nV2 AI phishing analysis completed!")

print(
    "Results saved to suspicious_urls_v2.csv"
)