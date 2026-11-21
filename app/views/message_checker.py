# -*- coding: utf-8 -*-
"""Page 3: the toy message classifier and its evidence."""

from __future__ import annotations

import pandas as pd
import streamlit as st

import charts
from classifier import (
    cross_validated_accuracy,
    predict_message,
    score_training_messages,
    suspicious_signals,
    train,
)
from data_loader import DataBundle
from theme import footer, hero, note, predict_card, section

EXAMPLES = [
    "",
    "Your account will close today verify now",
    "Urgent password reset required",
    "Team meeting moved to 10:30",
    "Please review the attached safety checklist",
    "You won a prize claim it now",
    "Your parcel is held pay the fee now",
]


def _style_predictions(frame: pd.DataFrame):
    """Green when the prediction matches the label, red when it does not."""

    def row_colour(row: pd.Series) -> list[str]:
        colour = "color: #7ce3b0;" if row["correct"] else "color: #ff9aac; font-weight: 600;"
        return [colour] * len(row)

    return frame.style.apply(row_colour, axis=1)


def render(bundle: DataBundle) -> None:
    messages = bundle.messages
    vectorizer, model = train(messages)
    accuracy = cross_validated_accuracy(messages)
    suspicious_examples = int((messages["label"] == "suspicious").sum())
    safe_examples = int((messages["label"] == "safe").sum())

    hero(
        "Message checker",
        "A deliberately tiny Naive Bayes model that marks practice messages as safe or "
        "suspicious. It counts words - it does not understand meaning - so treat its answer as "
        "one clue among several.",
        [
            f"{len(messages)} labelled training messages",
            f"Cross-validated accuracy <strong>{accuracy:.0%}</strong>",
            "Toy model - not a real mail filter",
        ],
    )

    metrics = st.columns(4, gap="medium")
    metrics[0].metric("Training messages", len(messages))
    metrics[1].metric("Safe examples", safe_examples)
    metrics[2].metric("Suspicious examples", suspicious_examples)
    metrics[3].metric(
        "Cross-validated accuracy",
        f"{accuracy:.0%}" if accuracy else "n/a",
        help="Measured on messages the model did not train on",
    )

    check_column, learn_column = st.columns([1.15, 1], gap="large")

    with check_column:
        section("Check a message", "Type your own or pick a practice example")
        example = st.selectbox(
            "Practice examples",
            EXAMPLES,
            format_func=lambda value: value or "Choose an example...",
            key="mc_example",
        )
        typed = st.text_area(
            "Message text",
            key="mc_text",
            height=110,
            placeholder="Type a practice message here, for example: Your account will close today",
        )
        message = typed.strip() or example

        if message:
            result = predict_message(vectorizer, model, message)
            if result["unknown"]:
                st.info(
                    "None of those words appear in the training messages, so the model has no "
                    "basis for a prediction. This is an honest 'I do not know', not a bug.",
                    icon="\u2139\ufe0f",
                )
            else:
                note_text = (
                    "Pressure words were found in the message."
                    if result["label"] == "suspicious"
                    else "No strong pressure pattern was found."
                )
                predict_card(result["label"], result["confidence"], note_text)
                st.progress(result["confidence"], text=f"Model confidence {result['confidence']:.0%}")
                if result["signals"]:
                    chips = "".join(f'<span class="nt-word">{word}</span>' for word in result["signals"])
                    st.markdown(
                        f"**Words the model recognised**  \n{chips}",
                        unsafe_allow_html=True,
                    )
                st.caption(
                    "Confidence is not correctness. With 44 training messages, a confident wrong "
                    "answer is still possible."
                )
        else:
            st.caption("The result card appears here once you type or choose a message.")

        note(
            "<strong>Model warning:</strong> this is a toy model trained on a few dozen "
            "messages. Cyber defenders use predictions as clues, not final proof, and always "
            "check the sender and the link."
        )

    with learn_column:
        section("What the model learned", "The words that push a message towards suspicious")
        st.pyplot(charts.suspicious_signals(suspicious_signals(vectorizer, model, 8)))
        st.caption(
            "Naive Bayes compares how often each word appears in safe and suspicious examples. "
            "Word pairs such as 'password reset' are counted too. No grammar, sender, or link "
            "reputation is used."
        )

    # ------------------------------------------------------- batch review
    section("Score every practice message", "Predicted label next to the real label")
    scored = score_training_messages(messages, vectorizer, model)
    training_accuracy = scored["correct"].mean()
    st.caption(
        f"Training-set accuracy is {training_accuracy:.0%}, but that only shows the model has "
        f"memorised these examples. The honest estimate is the {accuracy:.0%} cross-validated "
        "score at the top of the page."
    )

    display = scored[["id", "message", "label", "predicted", "confidence", "correct", "reason"]].copy()
    display["confidence"] = display["confidence"].map(lambda value: f"{value:.0%}")
    st.dataframe(
        _style_predictions(display),
        hide_index=True,
        width="stretch",
        height=360,
        column_config={
            "id": st.column_config.NumberColumn("ID", width="small"),
            "correct": st.column_config.CheckboxColumn("match"),
        },
        alt="Practice messages with real label, predicted label, confidence, and reason",
    )
    st.download_button(
        "Download the scored message table",
        scored.to_csv(index=False).encode(),
        file_name="message_predictions.csv",
        mime="text/csv",
        key="mc_download",
    )

    with st.expander("How I would improve this classifier"):
        st.markdown(
            "- Add more examples, especially short messages, because the model has only 44 rows.\n"
            "- Keep the safe and suspicious classes balanced so one side does not dominate.\n"
            "- Test on messages written by someone else; that is a fairer challenge than reusing "
            "the training rows.\n"
            "- Compare against a rule like 'contains a link and a pressure word' and explain "
            "which approach makes fewer mistakes."
        )

    footer()
