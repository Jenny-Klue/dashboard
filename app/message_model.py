# -*- coding: utf-8 -*-
"""Train the toy message classifier and print a few predictions.

Run from the project folder:  python app/message_model.py
"""

from classifier import predict_message, suspicious_signals, train
from data_loader import load_messages

messages = load_messages()
vectorizer, model = train(messages)

examples = [
    "urgent password reset required",
    "team meeting at 11",
    "claim your prize now",
    "please review the attached report",
    "your account will close today verify now",
    "the build finished successfully",
]

print("Toy message classifier")
print("=" * 70)
for text in examples:
    result = predict_message(vectorizer, model, text)
    label = result["label"] or "unknown"
    print(f"{text:<48} => {label:<10} ({result['confidence']:.0%} confidence)")

print("\nWords that most strongly suggest 'suspicious':")
print(", ".join(word for word, _ in suspicious_signals(vectorizer, model, 10)))
print("\nWarning: this model is a teaching toy, not a real phishing filter.")
