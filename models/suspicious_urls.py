import pandas as pd
from transformers import pipeline

print("Loading AI phishing detection model...")

classifier = pipeline(
    "text-classification",
    model="imanoop7/bert-phishing-detector"
)


def classify_url(url):

    try:

        result = classifier(
            str(url),
            truncation=True
        )[0]

        label = result["label"]
        confidence = result["score"]

        if label == "LABEL_1":
            status = "Suspicious"
        else:
            status = "Safe"

        return status, confidence

    except Exception as e:

        print(
            f"Error analyzing {url}: {e}"
        )

        return "Unknown", 0.0


df = pd.read_csv(
    "history.csv"
)

results = []

for _, row in df.iterrows():

    url = row["URL"]

    status, confidence = classify_url(
        url
    )

    results.append({

        "Browser": row["Browser"],

        "URL": url,

        "Title": row.get(
            "Title",
            ""
        ),

        "Status": status,

        "Confidence": round(
            confidence * 100,
            2
        )
    })


result_df = pd.DataFrame(
    results
)

result_df.to_csv(
    "suspicious_urls.csv",
    index=False
)

print("\n======================================")
print(" AI PHISHING DETECTION COMPLETED")
print("======================================")

print(result_df)

print(
    "\nResults saved to suspicious_urls.csv"
)