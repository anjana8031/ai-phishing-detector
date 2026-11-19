import streamlit as st
import joblib
import re
import pandas as pd
from urllib.parse import urlparse

# Saved AI Model load karna
model = joblib.load("phishing_detector_model.pkl")

def extract_url_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_https'] = 1 if url.startswith("https://") else 0
    features['has_at_symbol'] = 1 if "@" in url else 0
    domain = urlparse(url).netloc
    features['hyphen_count'] = domain.count('-')
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features['has_ip'] = 1 if re.search(ip_pattern, domain) else 0
    suspicious_words = ['login', 'verify', 'update', 'bank', 'free', 'win', 'kyc', 'urgent', 'secure']
    features['suspicious_word_count'] = sum(word in url.lower() for word in suspicious_words)
    return features

def explain_reason(feat):
    reasons = []
    if feat['has_https'] == 0:
        reasons.append("⚠️ Website mein secure HTTPS lock nahi hai.")
    if feat['hyphen_count'] >= 2:
        reasons.append("⚠️ Domain name mein bohot saare hyphens ('-') hain (nakli websites ki pehchan).")
    if feat['suspicious_word_count'] >= 1:
        reasons.append("⚠️ Link mein darane ya lalach dene wale shabd (jaise kyc, urgent, bank, free) hain.")
    if feat['has_at_symbol'] == 1:
        reasons.append("⚠️ Link mein '@' symbol chhupa hai jo user ko fake site par bhejta hai.")
    if not reasons:
        reasons.append("✅ Link ka structure clean aur safe lag raha hai.")
    return reasons

# --- WEBSITE DESIGN (UI) ---
st.set_page_config(page_title="AI Phishing Detector", page_icon="🛡️")
st.title("🛡️ AI Phishing & Scam Link Detector")
st.write("Apne WhatsApp, SMS, ya Email par aaya koi bhi link neeche paste karein aur check karein ki woh **Safe** hai ya **Fraud**.")

user_url = st.text_input("🔗 Yahan Link Paste Karein:", placeholder="https://example.com")

if st.button("🔍 Check Link Now"):
    if user_url:
        feat = extract_url_features(user_url)
        df = pd.DataFrame([feat])
        pred = model.predict(df)[0]
        risk = model.predict_proba(df)[0][1] * 100
        
        st.subheader("📊 Result:")
        if pred == 1:
            st.error(f"🔴 DANGER: Yeh ek Phishing / Scam Link ho sakta hai! (Risk Score: {risk:.1f}%)")
        else:
            st.success(f"🟢 SAFE: Yeh link surakshit lag raha hai! (Risk Score: {risk:.1f}%)")
            
        st.subheader("🧠 AI Explanation (Kyun?):")
        for r in explain_reason(feat):
            st.write(r)
    else:
        st.warning("Kripya pehle koi link paste karein!")
