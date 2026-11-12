# -*- coding: utf-8 -*-
"""Page 4: checklist, analyst notes, and the generated incident report."""

from __future__ import annotations

import streamlit as st

from config import ANALYST_NAME, REPORTS_DIR, SHIFT_LABEL
from data_loader import DataBundle
from report_builder import build_context, build_markdown, key_findings
from theme import footer, hero, note, section

CHECKLIST = [
    "The dashboard starts without errors.",
    "Login, network, and message data are visible.",
    "At least three metrics and two alert rules are working.",
    "At least one chart and the message checker are working.",
    "The three most important findings have evidence attached.",
    "The risk level is explained in my own words.",
    "Screenshots are saved in the screenshots folder.",
    "The report contains toy data only, with no private information.",
]


def render(bundle: DataBundle) -> None:
    context = build_context(bundle)
    risk = context["risk"]

    hero(
        "Incident report",
        "Turn the alerts into a short, evidence-based report: what happened, how serious it is, "
        "and what NovaTech should do next. The draft below is generated from the same rules as "
        "the dashboard.",
        [
            f"Analyst <strong>{ANALYST_NAME}</strong>",
            f"Risk <strong>{risk['score']}/100</strong> &middot; {risk['band']}",
            "Markdown report",
            "Toy logs only",
        ],
    )

    metrics = st.columns(4, gap="medium")
    metrics[0].metric("Alerts in report", risk["total"])
    metrics[1].metric("Critical", risk["counts"]["Critical"])
    metrics[2].metric("High", risk["counts"]["High"])
    metrics[3].metric("Messages analysed", len(bundle.messages))

    checklist_column, download_column = st.columns([1.1, 1], gap="large")

    with checklist_column:
        section("Final product checklist", "Tick each item when it is true")
        checked = 0
        for index, item in enumerate(CHECKLIST):
            if st.checkbox(item, key=f"report_check_{index}"):
                checked += 1
        st.progress(checked / len(CHECKLIST), text=f"{checked} of {len(CHECKLIST)} complete")
        if checked == len(CHECKLIST):
            st.success("Checklist complete. The project is ready to showcase.", icon="\u2705")

        section("Analyst notes", "Saved with your report draft")
        notes = st.text_area(
            "Notes for the report",
            key="investigation_notes",
            height=170,
            placeholder=(
                "Example: the admin account is the priority. It failed four times from an "
                "outside address (203.0.113.45), succeeded at 09:15, then downloaded "
                "staff_list.csv at 09:17."
            ),
        )

    with download_column:
        section("Download evidence", "Everything a facilitator needs to check")
        report_markdown = build_markdown(context, notes=notes)
        st.download_button(
            "Download Incident_Report.md",
            report_markdown.encode("utf-8"),
            file_name="Incident_Report.md",
            mime="text/markdown",
            key="report_download_md",
            width="stretch",
        )
        st.download_button(
            "Download the factory alerts (CSV)",
            context["factory_alerts"].to_csv(index=False).encode(),
            file_name="factory_alerts.csv",
            mime="text/csv",
            key="report_download_alerts",
            width="stretch",
        )
        st.download_button(
            "Download the message evidence (CSV)",
            context["bundle"].messages.to_csv(index=False).encode(),
            file_name="messages_evidence.csv",
            mime="text/csv",
            key="report_download_messages",
            width="stretch",
        )
        st.caption(
            f"The saved copy lives at reports/Incident_Report.md. Use "
            "`python app/report_builder.py` to refresh it after changing data or thresholds."
        )
        if notes:
            st.success("Your notes will be added as section 9 of the report.", icon="\u270e")

    section("Auto-generated findings", "Use these as the backbone of your report")
    for finding in key_findings(context):
        st.markdown(f"- {finding}")

    section("Report preview", "This is the exact text in the download button")
    with st.expander("Show the full generated report", expanded=False):
        st.markdown(report_markdown)

    existing = REPORTS_DIR / "Incident_Report.md"
    if existing.exists():
        st.caption(
            f"Last saved report: {existing.name} "
            f"({existing.stat().st_size:,} bytes). Shift: {SHIFT_LABEL}."
        )

    note(
        "<strong>Before you submit:</strong> read the generated report and rewrite the summary "
        "and reflection in your own voice. A strong report explains the evidence and admits "
        "what it cannot prove."
    )

    footer()
