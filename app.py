import streamlit as st
import joblib
import re
import pandas as pd
from urllib.parse import urlparse

model = joblib.load("phishing_detector_model.pkl")

def extract_url_features(url):
    url = url.strip()
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
        reasons.append("⚠️ Missing secure HTTPS encryption lock.")
    if feat['hyphen_count'] >= 2:
        reasons.append("⚠️ Multiple hyphens ('-') detected in the domain name (common in fake websites).")
    if feat['suspicious_word_count'] >= 1:
        reasons.append("⚠️ Suspicious or urgency-inducing keywords detected (e.g., kyc, urgent, bank, free).")
    if feat['has_at_symbol'] == 1:
        reasons.append("⚠️ Contains '@' symbol used to redirect users to malicious sites.")
    if not reasons:
        reasons.append("✅ URL structure and security indicators appear clean and safe.")
    return reasons

st.set_page_config(page_title="AI Phishing Detector", page_icon="🛡️")
st.title("🛡️ AI Phishing & Scam Link Detector")
st.write("Paste any URL from WhatsApp, SMS, or Email below to check in real time whether it is **Safe** or a **Phishing Scam**.")

user_url = st.text_input("🔗 Enter or Paste URL Here:", placeholder="https://example.com")

if st.button("🔍 Check Link Now"):
    clean_url = user_url.strip()
    if clean_url:
        feat = extract_url_features(clean_url)
        df = pd.DataFrame([feat])
        risk = float(model.predict_proba(df)[0][1]) * 100
        
        st.subheader("📊 Analysis Result:")
        if risk >= 65.0:
            st.error(f"🔴 DANGER: High probability of a Phishing / Scam Link! (Risk Score: {risk:.1f}%)")
        else:
            st.success(f"🟢 SAFE: This link appears legitimate and safe. (Risk Score: {risk:.1f}%)")
            
        st.subheader("🧠 AI Explanation:")
        for r in explain_reason(feat):
            st.write(r)
    else:
        st.warning("Please enter a URL first!")
