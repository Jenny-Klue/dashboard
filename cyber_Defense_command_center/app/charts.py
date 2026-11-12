# -*- coding: utf-8 -*-
"""Matplotlib charts used by the dashboard.

They share one small style helper so every chart matches the dark theme.
"""

from __future__ import annotations

import matplotlib
import matplotlib.dates as mdates

matplotlib.use("Agg")  # no interactive windows: Streamlit renders the figures

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.lines import Line2D

from config import ACCENT, SEVERITY_COLORS, SEVERITY_ORDER

TEXT = "#a7b9cd"
MUTED = "#6f849b"
GRID = "#22324a"
TRACK = "#1b2a3d"


def _figure(width: float, height: float):
    figure, axes = plt.subplots(figsize=(width, height), dpi=135)
    figure.patch.set_alpha(0)
    axes.set_facecolor("none")
    for side in ("top", "right"):
        axes.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        axes.spines[side].set_color(GRID)
    axes.tick_params(colors=TEXT, labelsize=8.5, length=0)
    axes.grid(axis="x", color=GRID, linewidth=0.6, alpha=0.55)
    axes.set_axisbelow(True)
    return figure, axes


def failed_logins_by_user(logins: pd.DataFrame, threshold: int = 3) -> plt.Figure:
    """Horizontal bars of failed attempts per user, alerting users in orange."""
    counts = (
        logins[logins["result"] == "failed"]
        .groupby("user")
        .size()
        .sort_values(ascending=True)
    )
    if counts.empty:
        counts = pd.Series({"no failures": 0})

    colours = [
        SEVERITY_COLORS["High"] if value >= threshold else SEVERITY_COLORS["Low"]
        for value in counts.values
    ]
    figure, axes = _figure(5.6, 2.9)
    bars = axes.barh(counts.index, counts.values, color=colours, height=0.62)
    axes.bar_label(bars, padding=3, color=TEXT, fontsize=8)
    axes.set_xlabel("failed logins", color=MUTED, fontsize=8)
    axes.set_xlim(0, max(counts.values) + 2)
    axes.grid(axis="x", visible=False)
    axes.grid(axis="y", visible=False)
    axes.legend(
        handles=[
            Line2D([0], [0], marker="s", linestyle="", markersize=7,
                   markerfacecolor=SEVERITY_COLORS["High"], label=f"{threshold}+ failures"),
            Line2D([0], [0], marker="s", linestyle="", markersize=7,
                   markerfacecolor=SEVERITY_COLORS["Low"], label="below threshold"),
        ],
        loc="lower right", frameon=False, fontsize=7.5, labelcolor=TEXT,
    )
    return figure


def login_result_donut(logins: pd.DataFrame) -> plt.Figure:
    """Success vs failed split for the login log."""
    counts = logins["result"].value_counts()
    values = [int(counts.get("success", 0)), int(counts.get("failed", 0))]
    labels = ["success", "failed"]
    colours = [SEVERITY_COLORS["Low"], SEVERITY_COLORS["Critical"]]

    figure, axes = plt.subplots(figsize=(3.4, 2.9), dpi=135)
    figure.patch.set_alpha(0)
    axes.pie(
        values,
        colors=colours,
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.34, "edgecolor": "none"},
    )
    axes.text(0, 0.08, str(sum(values)), ha="center", va="center",
              color="#eef6ff", fontsize=19, fontweight="bold")
    axes.text(0, -0.2, "login events", ha="center", va="center", color=MUTED, fontsize=8)
    axes.legend(
        [f"{label}  {value}" for label, value in zip(labels, values)],
        loc="lower center", bbox_to_anchor=(0.5, -0.18), ncol=2,
        frameon=False, fontsize=8, labelcolor=TEXT,
    )
    return figure


def network_by_device(network: pd.DataFrame) -> plt.Figure:
    """Stacked bars: normal vs suspicious bytes for each device."""
    grouped = (
        network.assign(
            normal_bytes=network["bytes_sent"].where(network["category"] != "suspicious", 0),
            risky_bytes=network["bytes_sent"].where(network["category"] == "suspicious", 0),
        )
        .groupby("device")[["normal_bytes", "risky_bytes"]]
        .sum()
        .sort_values(["risky_bytes", "normal_bytes"])
    )
    grouped = grouped / 1000  # show kilobytes

    figure, axes = _figure(5.6, 2.9)
    axes.barh(grouped.index, grouped["normal_bytes"], color=ACCENT, height=0.6, label="normal")
    axes.barh(
        grouped.index, grouped["risky_bytes"], left=grouped["normal_bytes"],
        color=SEVERITY_COLORS["High"], height=0.6, label="suspicious",
    )
    axes.set_xlabel("kilobytes sent", color=MUTED, fontsize=8)
    axes.grid(axis="x", color=GRID, linewidth=0.6, alpha=0.55)
    axes.grid(axis="y", visible=False)
    axes.legend(frameon=False, fontsize=7.5, labelcolor=TEXT, loc="lower right")
    return figure


def risk_gauge(score: int, band: str, colour: str) -> plt.Figure:
    """Donut gauge for the 0-100 teaching risk score."""
    figure, axes = plt.subplots(figsize=(3.2, 2.6), dpi=140)
    figure.patch.set_alpha(0)
    axes.pie(
        [score, max(0, 100 - score)],
        colors=[colour, TRACK],
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.24, "edgecolor": "none"},
    )
    axes.text(0, 0.12, str(score), ha="center", va="center",
              color="#f2f8ff", fontsize=30, fontweight="bold")
    axes.text(0, -0.18, "/ 100", ha="center", va="center", color=MUTED, fontsize=9)
    axes.text(0, -0.42, band.upper(), ha="center", va="center", color=colour,
              fontsize=9, fontweight="bold")
    return figure


def event_timeline(factory: pd.DataFrame) -> plt.Figure:
    """Scatter of every factory event over the shift, coloured by severity."""
    figure, axes = _figure(11.2, 3.6)
    order = sorted(factory["device"].unique())
    positions = {device: index for index, device in enumerate(order)}

    for severity in reversed(SEVERITY_ORDER):
        subset = factory[factory["severity"] == severity]
        if subset.empty:
            continue
        axes.scatter(
            subset["timestamp"],
            subset["device"].map(positions),
            s=58 if severity in ("Critical", "High") else 34,
            color=SEVERITY_COLORS[severity],
            edgecolor="#08111c",
            linewidth=0.6,
            alpha=0.92,
            label=severity,
            zorder=3 if severity in ("Critical", "High") else 2,
        )

    axes.set_yticks(range(len(order)), order)
    axes.grid(axis="y", color=GRID, linewidth=0.5, alpha=0.35)
    axes.grid(axis="x", color=GRID, linewidth=0.5, alpha=0.35)
    axes.set_ylim(-0.7, len(order) - 0.3)
    axes.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    axes.tick_params(axis="x", labelsize=8, colors=TEXT)
    axes.set_xlabel("time on 03 Feb 2026", color=MUTED, fontsize=8)
    axes.legend(frameon=False, fontsize=8, labelcolor=TEXT, loc="upper right", ncol=4)

    first_critical = factory[factory["severity"] == "Critical"]["timestamp"].min()
    if pd.notna(first_critical):
        axes.axvline(first_critical, color=SEVERITY_COLORS["Critical"],
                     linewidth=0.9, linestyle=(0, (3, 3)), alpha=0.7)
        axes.annotate(
            "critical chain",
            xy=(first_critical, len(order) - 0.55),
            xytext=(8, 0), textcoords="offset points",
            color=SEVERITY_COLORS["Critical"], fontsize=7.5, va="center",
        )
    return figure


def event_type_counts(factory: pd.DataFrame) -> plt.Figure:
    """How many events of each type were logged."""
    counts = factory["event_type"].value_counts().sort_values()
    colours = [
        SEVERITY_COLORS["Critical"] if event_type in ("FILE_DOWNLOAD", "USB_INSERTED")
        else ACCENT
        for event_type in counts.index
    ]
    figure, axes = _figure(5.2, 2.9)
    bars = axes.barh(counts.index, counts.values, color=colours, height=0.6)
    axes.bar_label(bars, padding=3, color=TEXT, fontsize=8)
    axes.set_xlabel("events", color=MUTED, fontsize=8)
    axes.set_xlim(0, counts.max() * 1.18)
    axes.grid(axis="x", visible=False)
    axes.grid(axis="y", visible=False)
    return figure


def severity_bars(counts: pd.DataFrame) -> plt.Figure:
    """Vertical bars: how many alerts fired at each severity level."""
    values = (
        counts.set_index("severity")
        .reindex(SEVERITY_ORDER, fill_value=0)["alerts"]
    )
    colours = [SEVERITY_COLORS[severity] for severity in values.index]

    figure, axes = _figure(3.8, 2.6)
    bars = axes.bar(values.index, values.values, color=colours, width=0.58)
    axes.bar_label(bars, padding=3, color=TEXT, fontsize=8)
    axes.set_ylabel("alerts", color=MUTED, fontsize=8)
    axes.set_ylim(0, max(int(values.max()), 1) * 1.25)
    axes.grid(axis="x", visible=False)
    axes.grid(axis="y", color=GRID, linewidth=0.6, alpha=0.55)
    return figure


def suspicious_signals(signals: list[tuple[str, float]]) -> plt.Figure:
    """The words that push the classifier towards 'suspicious'."""
    if not signals:
        signals = [("no signals", 0.0)]
    labels = [word for word, _ in signals][::-1]
    values = [value for _, value in signals][::-1]

    figure, axes = _figure(6.0, 2.7)
    bars = axes.barh(labels, values, color=SEVERITY_COLORS["High"], height=0.55)
    axes.bar_label(bars, fmt="%.1f", padding=3, color=TEXT, fontsize=7.5)
    axes.set_xlabel("relative suspicion weight", color=MUTED, fontsize=8)
    axes.set_xlim(0, max(values) * 1.22 if max(values) else 1)
    axes.grid(axis="x", visible=False)
    axes.grid(axis="y", visible=False)
    return figure
