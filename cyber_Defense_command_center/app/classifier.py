# -*- coding: utf-8 -*-
"""A deliberately small, explainable message classifier.

The model counts words and word pairs, then uses a Naive Bayes classifier to
guess "safe" or "suspicious". It is a teaching model: tiny data, simple
features, and no understanding of meaning. Predictions are clues, never proof.
"""

from __future__ import annotations

import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import cross_val_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline


def train(messages: pd.DataFrame) -> tuple[CountVectorizer, MultinomialNB]:
    """Fit the vectorizer and model on the labelled practice messages."""
    vectorizer = CountVectorizer(ngram_range=(1, 2), lowercase=True)
    counts = vectorizer.fit_transform(messages["message"])
    model = MultinomialNB(alpha=0.3)
    model.fit(counts, messages["label"])
    return vectorizer, model


def predict_message(
    vectorizer: CountVectorizer, model: MultinomialNB, text: str
) -> dict:
    """Classify one message and report the strongest words it recognised."""
    features = vectorizer.transform([text])
    if features.nnz == 0:
        return {
            "label": None,
            "confidence": 0.0,
            "signals": [],
            "unknown": True,
        }

    probabilities = model.predict_proba(features)[0]
    classes = list(model.classes_)
    best = int(probabilities.argmax())
    signals = [
        word
        for word in vectorizer.build_analyzer()(text)
        if word in vectorizer.vocabulary_
    ]

    return {
        "label": classes[best],
        "confidence": float(probabilities[best]),
        "signals": list(dict.fromkeys(signals))[:8],
        "unknown": False,
    }


def suspicious_signals(
    vectorizer: CountVectorizer, model: MultinomialNB, limit: int = 8
) -> list[tuple[str, float]]:
    """Words the model treats as most suspicious, strongest first."""
    classes = list(model.classes_)
    if "suspicious" not in classes or "safe" not in classes:
        return []

    suspicious_index = classes.index("suspicious")
    safe_index = classes.index("safe")
    difference = model.feature_log_prob_[suspicious_index] - model.feature_log_prob_[safe_index]
    vocabulary = vectorizer.get_feature_names_out()

    order = difference.argsort()[::-1]
    signals = [
        (str(vocabulary[index]), float(difference[index]))
        for index in order
        if " " not in str(vocabulary[index])
    ]
    return signals[:limit]


def score_training_messages(
    messages: pd.DataFrame, vectorizer: CountVectorizer, model: MultinomialNB
) -> pd.DataFrame:
    """Show what the model predicts for every practice message."""
    counts = vectorizer.transform(messages["message"])
    predictions = model.predict(counts)
    confidence = model.predict_proba(counts).max(axis=1)

    scored = messages.copy()
    scored["predicted"] = predictions
    scored["confidence"] = confidence
    scored["correct"] = scored["predicted"] == scored["label"]
    return scored


def cross_validated_accuracy(messages: pd.DataFrame, folds: int = 4) -> float | None:
    """Estimate accuracy on messages the model has not memorised.

    Small data makes this rough. It is still more honest than scoring the model
    on the same messages it learned from.
    """
    smallest_class = messages["label"].value_counts().min()
    if smallest_class < 2:
        return None

    folds = min(folds, int(smallest_class))
    pipeline = make_pipeline(CountVectorizer(ngram_range=(1, 2)), MultinomialNB(alpha=0.3))
    scores = cross_val_score(pipeline, messages["message"], messages["label"], cv=folds)
    return float(scores.mean())
