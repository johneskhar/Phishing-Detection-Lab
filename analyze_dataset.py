import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from email import policy
from email.parser import BytesParser

# ---------------------------
# Step 1: Load dataset (EML files)
# ---------------------------
def load_emails(folder, label):
    data = []
    for filename in os.listdir(folder):
        if filename.endswith(".eml"):
            path = os.path.join(folder, filename)
            try:
                with open(path, "rb") as f:
                    msg = BytesParser(policy=policy.default).parse(f)
                    body = msg.get_body(preferencelist=("plain", "html"))
                    text = body.get_content() if body else ""
                    data.append((text, label))
            except Exception as e:
                print(f"Error reading {path}: {e}")
    return data

ham = load_emails("dataset/ham", "ham")
spam = load_emails("dataset/spam", "spam")

emails = pd.DataFrame(ham + spam, columns=["text", "label"])
print(f"Loaded {len(emails)} emails")

# ---------------------------
# Step 2: Train/test split
# ---------------------------
X_train, X_test, y_train, y_test = train_test_split(
    emails["text"], emails["label"], test_size=0.2, random_state=42
)

# ---------------------------
# Step 3: Vectorize & Train
# ---------------------------
vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = MultinomialNB()
model.fit(X_train_vec, y_train)

# ---------------------------
# Step 4: Evaluate
# ---------------------------
y_pred = model.predict(X_test_vec)

print("\nClassification Report:\n", classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred, labels=["ham", "spam"])
sns.heatmap(cm, annot=True, fmt="d", xticklabels=["ham", "spam"], yticklabels=["ham", "spam"])
plt.title("Confusion Matrix")
plt.savefig("outputs/confusion_matrix.png")
plt.close()

# ---------------------------
# Step 5: Save model
# ---------------------------
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/phishing_model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

print("✅ Model and vectorizer saved in /models/")
