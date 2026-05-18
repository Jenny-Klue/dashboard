import pandas as pd
import streamlit as st
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
st.set_page_config(page_title="Cyber Defense Command Centre", layout="wide")
st.title("Cyber Defense Command Centre")
st.write("Safe practice dashboard for toy cyber security logs.")
logins = pd.read_csv("data/login_logs.csv")
network = pd.read_csv("data/network_logs.csv")
messages = pd.read_csv("data/messages.csv")
col1, col2, col3 = st.columns(3)
col1.metric("Login events", len(logins))
col2.metric("Network events", len(network))
col3.metric("Messages", len(messages))
st.subheader("Login logs")
st.dataframe(logins)
st.subheader("Network logs")
st.dataframe(network)
st.subheader("Messages")
st.dataframe(messages)
st.subheader("Repeated failed login alerts")
failed = logins[logins["result"] == "failed"]
failed_counts = failed.groupby("user").size().reset_index(name="failed_attempts")
failed_counts["severity"] = failed_counts["failed_attempts"].apply(
 lambda x: "High" if x >= 4 else "Medium" if x >= 3 else "Low")
st.dataframe(failed_counts)
high_alerts = failed_counts[failed_counts["failed_attempts"] >= 3]
if len(high_alerts) > 0:
 st.warning("Investigation needed: repeated failed logins found.")
else:
 st.success("No repeated failed login alerts found.")
 st.subheader("Network risk alerts")
network["large_transfer"] = network["bytes_sent"] > 50000
network["network_alert"] = (network["category"] == "suspicious") | network["large_transfer"]
st.dataframe(network[network["network_alert"]])
st.subheader("Message checker")
X = messages["message"]
y = messages["label"]
vectorizer = CountVectorizer()
X_counts = vectorizer.fit_transform(X)
model = MultinomialNB()
model.fit(X_counts, y)
user_message = st.text_input("Type a practice message to check")
if user_message:
 prediction = model.predict(vectorizer.transform([user_message]))[0]
 if prediction == "suspicious":
    st.error("Prediction: suspicious")
 else:
    st.success("Prediction: safe")