import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
messages = pd.read_csv("data/messages.csv")
X = messages["message"]
y = messages["label"]
vectorizer = CountVectorizer()
X_counts = vectorizer.fit_transform(X)
model = MultinomialNB()
model.fit(X_counts, y)
examples = [
 "urgent password reset required",
 "team meeting at 11",
 "claim your prize now",
]
example_counts = vectorizer.transform(examples)
predictions = model.predict(example_counts)
for text, prediction in zip(examples, predictions):
 print(text, "=>", prediction)
