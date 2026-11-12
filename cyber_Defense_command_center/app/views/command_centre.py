# -*- coding: utf-8 -*-
"""Page 1: the shift overview and the starter-log alerts."""

from __future__ import annotations

import streamlit as st

import charts
from config import (
    ANALYST_NAME,
    FAILED_LOGIN_THRESHOLD,
    HIGH_FAILED_LOGIN_THRESHOLD,
    LARGE_TRANSFER_BYTES,
    PROJECT_NAME,
    SHIFT_LABEL,
    TEAM_NAME,
)
from data_loader import DataBundle
from detections import RULE_BOOK, severity_counts, simple_alerts
from theme import footer, hero, note, section, style_severity


def _highlight_result(frame):
    """Colour successful and failed login results for quick scanning."""

    def colour(value: str) -> str:
        if value == "failed":
            return "color: #ff9aac; font-weight: 600;"
        return "color: #7ce3b0;"

    return frame.style.map(colour, subset=["result"])


def _alert_table(alerts) -> None:
    """Show the alert feed with severity colours and the evidence text."""
    view = alerts[["alert_id", "time", "severity", "rule", "entity", "evidence"]].copy()
    st.dataframe(
        style_severity(view),
        hide_index=True,
        width="stretch",
        height=min(420, 42 + 35 * len(view)),
        alt="Alert feed with ID, time, severity, rule, affected entity, and evidence",
    )
    with st.expander("What should I do about these alerts?"):
        actions = alerts[["alert_id", "rule", "entity", "action"]].drop_duplicates("alert_id")
        for row in actions.itertuples():
            st.markdown(
                f"**{row.alert_id} - {row.rule}** ({row.entity})  \n{row.action}"
            )


def render(bundle: DataBundle) -> None:
    logins, network, messages = bundle.logins, bundle.network, bundle.messages
    alerts = simple_alerts(logins, network)
    counts = severity_counts(alerts)
    failed = logins[logins["result"] == "failed"]
    risky_messages = int((messages["label"] == "suspicious").sum())

    hero(
        PROJECT_NAME,
        "One screen for the login, network, and message evidence from the NovaTech practice "
        "shift. Read the alerts first, then check the raw rows behind them.",
        [
            '<span class="nt-dot"></span> <strong>Practice data loaded</strong>',
            f"Analyst <strong>{ANALYST_NAME}</strong>",
            f"{len(logins) + len(network) + len(messages)} events reviewed",
            "Toy logs only",
        ],
    )

    columns = st.columns(4, gap="medium")
    columns[0].metric("Events analysed", len(logins) + len(network) + len(messages))
    columns[1].metric("Failed logins", len(failed), help="Rows where result is failed")
    columns[2].metric("Alerts raised", len(alerts), help="Rules R1 and R2 on the starter logs")
    columns[3].metric(
        "Suspicious messages",
        f"{risky_messages}/{len(messages)}",
        help="Messages already labelled suspicious in the practice data",
    )

    critical_and_high = int(counts.loc[counts["severity"].isin(["Critical", "High"]), "alerts"].sum())
    if critical_and_high:
        st.warning(
            f"{critical_and_high} alert(s) are Critical or High. Start with the highest severity "
            "row and read its evidence before making a decision.",
            icon="\u26a0\ufe0f",
        )
    else:
        st.success("No Critical or High alerts in the starter logs.", icon="\u2705")

    # ------------------------------------------------------------ charts
    section("Shift at a glance", "Where the starter-log risk sits")
    left, middle, right = st.columns([1.1, 0.8, 1.1], gap="medium")
    with left:
        st.caption(f"Failed logins per user - alert at {FAILED_LOGIN_THRESHOLD}, high at {HIGH_FAILED_LOGIN_THRESHOLD}")
        st.pyplot(charts.failed_logins_by_user(logins, FAILED_LOGIN_THRESHOLD))
    with middle:
        st.caption("Login results")
        st.pyplot(charts.login_result_donut(logins))
    with right:
        st.caption(f"Network volume per device - large-transfer rule above {LARGE_TRANSFER_BYTES // 1000} KB")
        st.pyplot(charts.network_by_device(network))

    note(
        f"<strong>How to read this:</strong> {TEAM_NAME} uses three simple starter rules. "
        "An alert means 'check this', not 'this is an attack'. The evidence column always "
        "shows the rows that caused the alert."
    )

    # ------------------------------------------------------------ alerts
    section("Priority alerts", f"{len(alerts)} alerts from rules R1 and R2")
    if alerts.empty:
        st.success("No alerts found in the starter logs.")
    else:
        _alert_table(alerts)

    # ------------------------------------------------------------ logins
    section("Login activity", f"{len(logins)} rows - filter by user and result")
    filter_left, filter_right, filter_spacer = st.columns([1.4, 1, 1.6])
    users = sorted(logins["user"].unique())
    chosen_users = filter_left.multiselect("Users", users, default=users, key="cc_users")
    result_choice = filter_right.selectbox(
        "Result", ["All results", "success", "failed"], key="cc_result"
    )

    login_view = logins[logins["user"].isin(chosen_users)]
    if result_choice != "All results":
        login_view = login_view[login_view["result"] == result_choice]

    st.caption(f"{len(login_view)} of {len(logins)} login rows shown")
    st.dataframe(
        _highlight_result(login_view[["time", "user", "device", "result", "location"]]),
        hide_index=True,
        width="stretch",
        height=320,
        alt="Filtered login events",
    )
    st.download_button(
        "Download this login view",
        login_view[["time", "user", "device", "result", "location"]].to_csv(index=False).encode(),
        file_name="login_view.csv",
        mime="text/csv",
        key="cc_download_logins",
    )

    # ----------------------------------------------------------- network
    section("Network activity", f"{len(network)} rows - suspicious or large transfers are flagged")
    categories = sorted(network["category"].unique())
    chosen_categories = st.multiselect(
        "Traffic category", categories, default=categories, key="cc_categories"
    )
    network_view = network[network["category"].isin(chosen_categories)].copy()
    network_view["flag"] = [
        "Review" if flagged else "Normal" for flagged in network_view["flagged"]
    ]
    st.dataframe(
        network_view[["time", "device", "destination", "bytes_sent", "category", "flag"]],
        hide_index=True,
        width="stretch",
        height=320,
        column_config={
            "bytes_sent": st.column_config.NumberColumn("bytes sent", format="%d"),
            "flag": st.column_config.TextColumn("analyst flag"),
        },
        alt="Filtered network events with category and analyst flag",
    )
    st.download_button(
        "Download this network view",
        network_view.to_csv(index=False).encode(),
        file_name="network_view.csv",
        mime="text/csv",
        key="cc_download_network",
    )

    # ------------------------------------------------------------- rules
    section("Detection rule book", "The exact rules behind every alert on this page")
    with st.expander("Show the six project rules", expanded=False):
        st.dataframe(RULE_BOOK, hide_index=True, width="stretch")
        st.caption(
            "R1 and R2 run on the starter logs on this page. R3 to R6 run on the combined "
            "factory log on the Investigation page."
        )

    # ------------------------------------------------------------- notes
    section("Investigation notes", "These notes flow into your final report")
    notes = st.text_area(
        "What looks suspicious, and which evidence supports it?",
        key="investigation_notes",
        height=140,
        placeholder=(
            "Example: guest failed 7 logins from an unknown location, then succeeded at 09:19. "
            "The evidence is ALT-001 and rows 15-19 of login_logs.csv."
        ),
    )
    if notes:
        st.download_button(
            "Download my notes",
            notes.encode("utf-8"),
            file_name="investigation_notes.txt",
            mime="text/plain",
            key="cc_download_notes",
        )

    # -------------------------------------------------------- data quality
    with st.expander("Data quality checks (Data Detective evidence)"):
        st.dataframe(bundle.quality, hide_index=True, width="stretch")
        st.caption(
            "Every file loaded with the expected row count, no duplicate rows, and no empty "
            "cells. All data is fictional."
        )

    st.caption(f"Shift: {SHIFT_LABEL}")
    footer()
