# Phishing-Detection-Lab

## Project Overview
This project demonstrates an end-to-end phishing detection system that classifies emails using machine learning, extracts suspicious links, and forwards results to Splunk SIEM for real-time monitoring, dashboards, and alerts.

The solution replicates a real SOC workflow: detection → logging → SIEM ingestion → visualization → alerting.

## Key Features

- Dataset Training: Trained a Naive Bayes classifier on SpamAssassin dataset.

- Email Parsing: Extracted sender, subject, and body from .eml files.

- Suspicious Link Detection: Identified malicious indicators (IP-based URLs, suspicious TLDs, sender-domain mismatch).

- ML Classification: Classified emails as Ham (legit) or Spam/Phish with confidence scores.

- Splunk Integration: Forwarded results via HTTP Event Collector (HEC).

- Dashboarding: Built a Splunk Dashboard Studio view with:

📊 Phishing trend over time

📬 Top senders flagged

🌐 Extracted suspicious URLs

✅ Classification accuracy & confidence

- Alerting: Configured Splunk alert for high-confidence phishing detections.

## Workflow Architecture

1) Email Source → .eml dataset (SpamAssassin / custom samples)

2) Python Classifier → predict_eml.py (ML model + suspicious link scanner)

3) Log Output → CSV & JSON logs

4) Splunk HEC → Ingest classification results into index=main sourcetype=_json

5) Splunk Dashboard → Visualize phishing activity

6) SOC Analyst Actions → Review alerts, analyze suspicious links

## Example Output
**Classifier Result (Python):**
```json
{
  "file": "phish_1.eml",
  "sender": "billing@company-support.com",
  "subject": "Urgent - Overdue Invoice",
  "prediction": "spam",
  "confidence": 0.89,
  "suspicious_links": ["http://scammer-payments.com/invoice"]
}
```

## Future Improvements
- Automate threat enrichment with VirusTotal API.
- Add phishing email quarantine simulation.
- Extend with ELK stack (ElasticSearch, Logstash, Kibana).
