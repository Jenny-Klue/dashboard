# -*- coding: utf-8 -*-
"""Page 2: the combined factory log, the risk score, and the timeline."""

from __future__ import annotations

import pandas as pd
import streamlit as st

import charts
from config import (
    BRAND_NAME,
    LOGIN_WINDOW_MINUTES,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    SHIFT_LABEL,
)
from data_loader import DataBundle
from detections import (
    RULE_BOOK,
    investigation_alerts,
    recommendations,
    risk_score,
    severity_counts,
)
from theme import footer, hero, note, section, style_severity


def _event_view(factory: pd.DataFrame) -> pd.DataFrame:
    """Readable copy of the factory log for display."""
    view = factory.copy()
    view["time"] = view["timestamp"].dt.strftime("%H:%M:%S")
    view["date"] = view["timestamp"].dt.strftime("%d %b")
    return view[
        ["time", "date", "username", "ip_address", "device", "event_type", "severity", "details"]
    ]


def render(bundle: DataBundle) -> None:
    factory = bundle.factory
    alerts = investigation_alerts(factory)
    risk = risk_score(alerts)
    actions = recommendations(alerts)

    hero(
        "Investigation timeline",
        f"The combined {BRAND_NAME} log, ordered by time. The risk score is built from the alerts "
        "only, so raw log volume cannot inflate it.",
        [
            f'<span class="nt-dot" style="background:{risk["colour"]};'
            f'box-shadow:0 0 0 3px {risk["colour"]}22"></span>'
            f' <strong>Risk {risk["score"]}/100</strong> &middot; {risk["band"]}',
            f"{len(factory)} factory events",
            f"{len(alerts)} alerts from rules R3 to R6",
            "Toy logs only",
        ],
    )

    metrics = st.columns(4, gap="medium")
    metrics[0].metric(
        "Risk score",
        f"{risk['score']}/100",
        help="Weighted alert counts capped at 100",
    )
    metrics[1].metric("Critical alerts", risk["counts"]["Critical"])
    metrics[2].metric("High alerts", risk["counts"]["High"])
    metrics[3].metric("Medium alerts", risk["counts"]["Medium"])

    # ------------------------------------------------------- score + story
    gauge_column, story_column = st.columns([0.75, 1.9], gap="large")
    with gauge_column:
        st.pyplot(charts.risk_gauge(risk["score"], risk["band"], risk["colour"]))
        st.caption(
            "Weights: "
            + " / ".join(
                f"{severity} {SEVERITY_WEIGHTS[severity]}" for severity in SEVERITY_ORDER
            )
            + ". Capped at 100."
        )
    with story_column:
        st.markdown("#### What happened, in order")
        story = alerts[alerts["severity"].isin(["Critical", "High"])].head(4)
        for row in story.itertuples():
            st.markdown(f"- **{row.time} &middot; {row.severity} &middot; {row.rule}** - {row.evidence}")
        st.markdown(
            f"**Why this matters:** {risk['message']} The two Critical rows are the same "
            "admin session: a successful login after repeated failures, followed by a file "
            "download. Treat that chain as the main incident and the rest as supporting findings."
        )

    note(
        f"<strong>Threshold honesty:</strong> the burst rule needs "
        f"{LOGIN_WINDOW_MINUTES} minutes of context. Three failures can be a typo - the "
        "thabo alert stays Medium for that reason. A defender explains why an alert might be "
        "benign, not just why it fired."
    )

    # ------------------------------------------------------------ filters
    section("Filter the evidence", "Every table and the timeline react to these choices")
    filter_columns = st.columns([1.2, 1.2, 1.2, 0.9], gap="medium")
    severities = filter_columns[0].multiselect(
        "Severity", SEVERITY_ORDER, default=SEVERITY_ORDER, key="inv_severity"
    )
    devices = filter_columns[1].multiselect(
        "Device", sorted(factory["device"].unique()), default=sorted(factory["device"].unique()),
        key="inv_devices",
    )
    chosen_user = filter_columns[2].selectbox(
        "User",
        ["All users", *sorted(factory["username"].unique())],
        key="inv_users",
    )
    only_alerts = filter_columns[3].toggle("Only alerts", value=False, key="inv_only_alerts")

    filtered = factory[
        factory["severity"].isin(severities)
        & factory["device"].isin(devices)
    ]
    if chosen_user != "All users":
        filtered = filtered[filtered["username"] == chosen_user]
    visible_alerts = alerts[
        alerts["severity"].isin(severities)
    ]
    if only_alerts and not filtered.empty:
        flagged_entities = set(alerts["entity"])
        keep = filtered.apply(
            lambda row: f"{row['username']} @ {row['ip_address']}" in flagged_entities
            or row["severity"] == "Critical",
            axis=1,
        )
        filtered = filtered[keep]

    st.caption(
        f"{len(filtered)} of {len(factory)} events and {len(visible_alerts)} of {len(alerts)} "
        "alerts match the filters."
    )

    # ----------------------------------------------------------- timeline
    section("Event timeline", "Each dot is one event; colour shows severity")
    timeline_data = filtered if not filtered.empty else factory.iloc[0:0]
    if timeline_data.empty:
        st.info("No events match the current filters.")
    else:
        st.pyplot(charts.event_timeline(timeline_data))

    # ------------------------------------------------------------- alerts
    section("Rule-based alerts", "Click an alert ID in the table to read the linked action")
    if visible_alerts.empty:
        st.success("No alerts match the current filters.")
    else:
        alert_view = visible_alerts[
            ["alert_id", "time", "severity", "rule", "entity", "evidence"]
        ]
        st.dataframe(
            style_severity(alert_view),
            hide_index=True,
            width="stretch",
            height=min(430, 42 + 36 * len(alert_view)),
            alt="Factory-log alerts with severity, rule, entity, and evidence",
        )
        st.download_button(
            "Download the alert table",
            visible_alerts.to_csv(index=False).encode(),
            file_name="factory_alerts.csv",
            mime="text/csv",
            key="inv_download_alerts",
        )

    # ----------------------------------------------------------- actions
    section("Recommended defensive actions", "Ordered by what to do first")
    action_columns = st.columns(2, gap="medium")
    for index, action in enumerate(actions):
        with action_columns[index % 2]:
            st.markdown(
                f"**{action['priority']}. {action['title']}**  \n{action['detail']}"
            )

    # -------------------------------------------------------- event table
    section("Full event log", "Raw evidence behind the timeline")
    if filtered.empty:
        st.info("No events match the current filters.")
    else:
        st.dataframe(
            style_severity(_event_view(filtered)),
            hide_index=True,
            width="stretch",
            height=400,
            alt="Filtered factory event log",
        )
        st.download_button(
            "Download the filtered event log",
            filtered.to_csv(index=False).encode(),
            file_name="factory_events_filtered.csv",
            mime="text/csv",
            key="inv_download_events",
        )

    # ------------------------------------------------------------ charts
    section("Event mix", "What kind of activity fills the shift")
    chart_left, chart_right = st.columns([1.2, 1], gap="large")
    with chart_left:
        st.caption("Events by type")
        st.pyplot(charts.event_type_counts(filtered if not filtered.empty else factory))
    with chart_right:
        st.caption("Alerts by severity")
        st.pyplot(charts.severity_bars(severity_counts(visible_alerts)))
        st.caption(
            "Counts follow the filters above; the risk score always uses every alert. Critical "
            "and High alerts drive the score, while Medium and Low alerts weigh far less."
        )

    with st.expander("Rules running on this page"):
        st.dataframe(
            RULE_BOOK[RULE_BOOK["rule_id"].isin(["R3", "R4", "R5", "R6"])],
            hide_index=True,
            width="stretch",
        )

    st.caption(f"Shift: {SHIFT_LABEL}  |  Source: data/factory_security_logs.csv")
    footer()
