import os
import json
import joblib
import requests
from email import policy
from email.parser import BytesParser
import pandas as pd
import re

# ---------------------------
# Load model and vectorizer
# ---------------------------
model = joblib.load("models/phishing_model.pkl")
vectorizer = joblib.load("models/vectorizer.pkl")

# ---------------------------
# Splunk HEC Config
# ---------------------------
SPLUNK_HEC_URL = "https://127.0.0.1:8088/services/collector"
SPLUNK_HEC_TOKEN = "yoursplunktoken"
VERIFY_SSL = False  # change to True if using valid certs

# ---------------------------
# Helpers
# ---------------------------
def extract_email_content(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    sender = msg["From"] or "unknown"
    subject = msg["Subject"] or "No Subject"
    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""
    return sender, subject, text

def find_suspicious_links(text):
    urls = re.findall(r"http[s]?://\S+", text)
    suspicious = [u for u in urls if any(bad in u for bad in ["login", "verify", "update", "secure"])]
    return suspicious

def classify_email(path):
    sender, subject, body = extract_email_content(path)
    features = vectorizer.transform([body])
    prediction = model.predict(features)[0]
    confidence = max(model.predict_proba(features)[0])
    suspicious_links = find_suspicious_links(body)
    return {
        "file": os.path.basename(path),
        "sender": sender,
        "subject": subject,
        "prediction": prediction,
        "confidence": round(float(confidence), 2),
        "suspicious_links": suspicious_links
    }

def send_to_splunk(event):
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    payload = {"event": event}
    try:
        r = requests.post(SPLUNK_HEC_URL, headers=headers, json=payload, verify=VERIFY_SSL)
        if r.status_code == 200:
            print("✅ Sent to Splunk")
        else:
            print(f"⚠️ Splunk HEC error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"Error sending to Splunk: {e}")

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    folder = "dataset/spam"
    results = []
    for file in os.listdir(folder):
        if file.endswith(".eml"):
            path = os.path.join(folder, file)
            result = classify_email(path)
            results.append(result)
            send_to_splunk(result)
            print(result)

    # Save results
    pd.DataFrame(results).to_csv("outputs/spam_results.csv", index=False)
    with open("outputs/phishing_logs.json", "w") as f:
        json.dump(results, f, indent=2)

    print("✅ All results saved to /outputs/")

