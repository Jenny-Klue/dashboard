# -*- coding: utf-8 -*-
"""Odin FIT  - Cyber Defence Command Centre.

Run from the project folder:

    streamlit run app/dashboard.py

The app is a learning tool. Every log row is fictional practice data.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `import config`, `from views import ...` no matter which folder the
# terminal is in when Streamlit starts.
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import streamlit as st

from config import ANALYST_NAME, PROJECT_NAME, SHIFT_LABEL, TEAM_NAME
from data_loader import load_all
from theme import SHIELD_SVG, inject_css
from views import command_centre, incident_report, investigation, message_checker

st.set_page_config(
    page_title=f"{PROJECT_NAME} | {TEAM_NAME}",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data(show_spinner="Loading the practice logs...")
def get_bundle():
    """Read the four toy CSVs once per session."""
    return load_all()


PAGES = {
    "\U0001f3e0  Command Centre": command_centre.render,
    "\U0001f50e  Investigation": investigation.render,
    "\u2709\ufe0f  Message Checker": message_checker.render,
    "\U0001f4c4  Incident Report": incident_report.render,
}


def sidebar(bundle) -> callable:
    """Brand block, navigation, and the safety reminder."""
    with st.sidebar:
        st.markdown(
            f"""
            <div class="nt-side-brand">
              {SHIELD_SVG}
              <div>
                <b>{TEAM_NAME}</b>
                <small>{PROJECT_NAME}</small>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        page = st.radio(
            "Section",
            list(PAGES),
            label_visibility="collapsed",
            key="nav",
        )

        st.divider()
        st.caption("SAFE PRACTICE LAB")
        st.success(
            "Toy data only. Never scan, test, or investigate a real network, account, "
            "website, or person.",
            icon="\U0001f512",
        )

        st.divider()
        st.caption(f"**Analyst:** {ANALYST_NAME}")
        st.caption(f"**Shift:** {SHIFT_LABEL}")
        st.caption(f"**Data:** {len(bundle.factory)} factory events, {len(bundle.logins)} logins, "
                   f"{len(bundle.network)} transfers, {len(bundle.messages)} messages")

        if st.button("Reload practice data", width="stretch"):
            get_bundle.clear()
            st.rerun()

        st.divider()
        st.caption(
            "Personalised build: 6 detection rules, severity colouring, a 0-100 risk score, "
            "an event timeline, filters, and a generated report."
        )

    return PAGES[page]


def main() -> None:
    inject_css()
    bundle = get_bundle()
    page = sidebar(bundle)
    page(bundle)


if __name__ == "__main__":
    main()
