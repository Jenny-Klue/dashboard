# -*- coding: utf-8 -*-
"""Shared look and feel for the dashboard.

The CSS only styles the app chrome (header, metric cards, pills). All page
content is still normal Streamlit widgets, so the dashboard stays accessible
and works with the light or dark theme.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from config import ACCENT, SEVERITY_COLORS, TEAM_NAME

SHIELD_SVG = """
<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M12 2.5 4.5 5.4v5.7c0 4.7 3.1 8.8 7.5 10.4 4.4-1.6 7.5-5.7 7.5-10.4V5.4L12 2.5Z"
        fill="url(#shieldGradient)" stroke="#8ecbff" stroke-width="1.1"/>
  <path d="m8.6 11.9 2.3 2.3 4.5-4.6" stroke="#04121f" stroke-width="1.7"
        stroke-linecap="round" stroke-linejoin="round"/>
  <defs>
    <linearGradient id="shieldGradient" x1="4" y1="3" x2="20" y2="21" gradientUnits="userSpaceOnUse">
      <stop stop-color="#8ecbff"/>
      <stop offset="1" stop-color="#3f8cff"/>
    </linearGradient>
  </defs>
</svg>
"""


def inject_css() -> None:
    """Add the NovaTech visual identity on top of the dark theme."""
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap');

        .block-container {{ padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1420px; }}

        /* ---------------------------------------------------------- hero */
        .nt-hero {{
            position: relative;
            overflow: hidden;
            border: 1px solid #1e2d42;
            border-radius: 18px;
            padding: 26px 30px;
            margin-bottom: 22px;
            background:
                radial-gradient(1100px 240px at 8% -40%, rgba(90,176,255,.28), transparent 60%),
                linear-gradient(135deg, #0d1725 0%, #101c2d 55%, #0b1420 100%);
        }}
        .nt-hero:after {{
            content: ""; position: absolute; inset: 0;
            background-image: linear-gradient(rgba(255,255,255,.028) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(255,255,255,.028) 1px, transparent 1px);
            background-size: 42px 42px; mask-image: linear-gradient(to left, black, transparent 70%);
            pointer-events: none;
        }}
        .nt-hero-row {{ display: flex; gap: 18px; align-items: center; position: relative; z-index: 1; }}
        .nt-mark {{
            width: 54px; height: 54px; flex: 0 0 54px;
            display: grid; place-items: center;
            border-radius: 14px; border: 1px solid #27405c;
            background: rgba(90,176,255,.10);
            box-shadow: 0 0 28px rgba(90,176,255,.18) inset;
        }}
        .nt-mark svg {{ width: 32px; height: 32px; }}
        .nt-eyebrow {{
            font-family: 'Space Grotesk', sans-serif; font-size: .72rem; letter-spacing: .18em;
            text-transform: uppercase; color: #7fb8ea; margin-bottom: 4px;
        }}
        .nt-hero h1 {{
            font-family: 'Space Grotesk', sans-serif; font-size: 1.95rem; line-height: 1.15;
            margin: 0; color: #f4f8ff; letter-spacing: -.015em;
        }}
        .nt-hero p {{ margin: 7px 0 0; color: #9fb2c9; font-size: .95rem; max-width: 70ch; }}
        .nt-meta {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; position: relative; z-index: 1; }}
        .nt-pill {{
            display: inline-flex; align-items: center; gap: 7px;
            border: 1px solid #24374e; background: rgba(14,26,40,.72);
            border-radius: 999px; padding: 4px 11px;
            font-size: .74rem; color: #a9bdd4; letter-spacing: .02em;
        }}
        .nt-pill strong {{ color: #e7f1ff; font-weight: 600; }}
        .nt-dot {{ width: 7px; height: 7px; border-radius: 50%; background: #39d98a; box-shadow: 0 0 0 3px rgba(57,217,138,.15); }}

        /* -------------------------------------------------------- metrics */
        [data-testid="stMetric"] {{
            background: linear-gradient(180deg, rgba(20,34,52,.85), rgba(13,23,36,.85));
            border: 1px solid #1e2d42;
            border-radius: 14px;
            padding: 15px 18px;
            height: 100%;
        }}
        [data-testid="stMetricLabel"] p {{
            text-transform: uppercase; letter-spacing: .11em; font-size: .66rem !important;
            color: #8ba2bb !important; font-weight: 600; white-space: normal !important;
            line-height: 1.3 !important;
        }}
        [data-testid="stMetricValue"] {{ font-family: 'Space Grotesk', sans-serif; color: #f2f7ff; }}

        /* --------------------------------------------------------- layout */
        .nt-section {{
            display: flex; align-items: baseline; gap: 12px;
            margin: 26px 0 4px;
        }}
        .nt-section h2 {{
            font-family: 'Space Grotesk', sans-serif; font-size: 1.12rem; letter-spacing: .01em;
            color: #eaf2ff; margin: 0;
        }}
        .nt-section span {{ color: #7e93ab; font-size: .82rem; }}
        .nt-rule {{ height: 1px; background: linear-gradient(90deg, #23364d, transparent); margin: 6px 0 16px; }}

        /* ------------------------------------------------------- severity */
        .sev {{
            display: inline-block; padding: 2px 9px; border-radius: 999px;
            font-size: .70rem; font-weight: 600; letter-spacing: .05em;
            text-transform: uppercase; border: 1px solid transparent;
        }}
        .sev-critical {{ color: #ffb3c1; background: rgba(255,77,109,.14); border-color: rgba(255,77,109,.38); }}
        .sev-high     {{ color: #ffc2a0; background: rgba(255,143,77,.13); border-color: rgba(255,143,77,.36); }}
        .sev-medium   {{ color: #ffe19a; background: rgba(255,209,102,.12); border-color: rgba(255,209,102,.34); }}
        .sev-low      {{ color: #9cf0c6; background: rgba(57,217,138,.12); border-color: rgba(57,217,138,.32); }}

        /* ---------------------------------------------------- prediction */
        .nt-predict {{
            border-radius: 16px; padding: 22px 24px; margin: 6px 0 10px;
            border: 1px solid #24374e; background: rgba(13,23,36,.8);
        }}
        .nt-predict.bad {{ border-color: rgba(255,77,109,.5); background: rgba(58,16,27,.55); }}
        .nt-predict.good {{ border-color: rgba(57,217,138,.45); background: rgba(12,41,30,.5); }}
        .nt-predict .label {{ font-size: .72rem; letter-spacing: .16em; text-transform: uppercase; color: #93a8c1; }}
        .nt-predict .value {{ font-family: 'Space Grotesk', sans-serif; font-size: 1.75rem; margin-top: 4px; }}
        .nt-predict.bad .value {{ color: #ff8da1; }}
        .nt-predict.good .value {{ color: #62e0a5; }}
        .nt-predict .sub {{ color: #9fb2c9; font-size: .85rem; margin-top: 8px; }}

        .nt-word {{
            display: inline-block; margin: 3px 4px 0 0; padding: 3px 9px;
            border-radius: 7px; background: #142437; border: 1px solid #233a53;
            color: #b7d6f5; font-family: 'JetBrains Mono', monospace; font-size: .75rem;
        }}

        /* --------------------------------------------------------- misc */
        .nt-note {{
            border-left: 3px solid {ACCENT}; background: rgba(90,176,255,.07);
            padding: 11px 15px; border-radius: 0 10px 10px 0; color: #b9cee4; font-size: .86rem;
        }}
        .nt-footer {{
            color: #6d8299; font-size: .76rem; margin-top: 34px; padding-top: 14px;
            border-top: 1px solid #1b2938;
        }}
        div[data-testid="stSidebar"] .block-container {{ padding-top: 1.1rem; }}
        .nt-side-brand {{
            display: flex; gap: 10px; align-items: center; padding: 10px 12px;
            border: 1px solid #1e2d42; border-radius: 12px; background: rgba(16,202,255,.04);
            margin-bottom: 12px;
        }}
        .nt-side-brand svg {{ width: 26px; height: 26px; }}
        .nt-side-brand b {{ color: #eaf3ff; font-size: .86rem; display: block; }}
        .nt-side-brand small {{ color: #8097b0; font-size: .68rem; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def hero(title: str, subtitle: str, meta: list[str]) -> None:
    """Page banner with the shield mark and a row of status pills."""
    pills = "".join(f'<span class="nt-pill">{item}</span>' for item in meta)
    st.markdown(
        f"""
        <div class="nt-hero">
          <div class="nt-hero-row">
            <div class="nt-mark">{SHIELD_SVG}</div>
            <div>
              <div class="nt-eyebrow">{TEAM_NAME} &middot; safe practice lab</div>
              <h1>{title}</h1>
              <p>{subtitle}</p>
            </div>
          </div>
          <div class="nt-meta">{pills}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section(title: str, caption: str = "") -> None:
    """Consistent section heading with an optional caption."""
    st.markdown(
        f'<div class="nt-section"><h2>{title}</h2><span>{caption}</span></div>'
        '<div class="nt-rule"></div>',
        unsafe_allow_html=True,
    )


def predict_card(label: str, confidence: float, note: str) -> None:
    """Coloured prediction card used by the message checker."""
    mood = "bad" if label == "suspicious" else "good"
    st.markdown(
        f"""
        <div class="nt-predict {mood}">
          <div class="label">Classifier result</div>
          <div class="value">{label.title()}</div>
          <div class="sub">{confidence:.0%} confidence &middot; {note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def note(text: str) -> None:
    """Small highlighted analyst note."""
    st.markdown(f'<div class="nt-note">{text}</div>', unsafe_allow_html=True)


def footer() -> None:
    st.markdown(
        '<div class="nt-footer">Toy data only - no real systems, accounts, or people were '
        "investigated. Built for the FIT Phase 2 Cyber Security project.</div>",
        unsafe_allow_html=True,
    )


def style_severity(frame: pd.DataFrame, column: str = "severity") -> pd.io.formats.style.Styler:
    """Colour the severity column of a table for quick scanning."""

    def colour(value: str) -> str:
        return (
            f"background-color: {SEVERITY_COLORS.get(value, '#1b2938')}22;"
            f"color: {SEVERITY_COLORS.get(value, '#c9d6e5')};"
            "font-weight: 600;"
        )

    styler = frame.style
    return styler.map(colour, subset=[column])
