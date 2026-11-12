# -*- coding: utf-8 -*-
"""Detection rules for the Odin Fit practice logs.

Each rule is deliberately small and readable. A rule never proves an attack:
it only says "a defender should look at this". The evidence column records why
the alert fired so the finding can be explained in the incident report.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd

from config import (
    FAILED_LOGIN_THRESHOLD,
    HIGH_FAILED_LOGIN_THRESHOLD,
    LOGIN_WINDOW_MINUTES,
    RISK_BANDS,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
)

ALERT_COLUMNS = [
    "alert_id",
    "time",
    "severity",
    "rule_id",
    "rule",
    "entity",
    "evidence",
    "action",
    "source",
]

# Rules produce everything except the ID; combine_alerts() adds that after sorting.
RULE_COLUMNS = ALERT_COLUMNS[1:]

RULE_BOOK = pd.DataFrame(
    [
        {
            "rule_id": "R1",
            "rule": "Repeated failed logins",
            "what_it_looks_for": f"{FAILED_LOGIN_THRESHOLD}+ failures for one user",
            "severity": "High at 4+ failures, otherwise Medium",
            "data": "login_logs.csv",
        },
        {
            "rule_id": "R2",
            "rule": "Risky network traffic",
            "what_it_looks_for": "Suspicious destination or more than 50 KB sent",
            "severity": "High for repeated suspicious traffic, otherwise Medium",
            "data": "network_logs.csv",
        },
        {
            "rule_id": "R3",
            "rule": "Login burst in a short window",
            "what_it_looks_for": f"{FAILED_LOGIN_THRESHOLD}+ failures within {LOGIN_WINDOW_MINUTES} minutes for one user and IP",
            "severity": "High at 4+ failures, otherwise Medium",
            "data": "factory_security_logs.csv",
        },
        {
            "rule_id": "R4",
            "rule": "Critical event recorded",
            "what_it_looks_for": "Any log row already marked CRITICAL",
            "severity": "Critical",
            "data": "factory_security_logs.csv",
        },
        {
            "rule_id": "R5",
            "rule": "Risky removable media",
            "what_it_looks_for": "USB drive on a server or a file opened from removable media",
            "severity": "High",
            "data": "factory_security_logs.csv",
        },
        {
            "rule_id": "R6",
            "rule": "Password reset from an unusual address",
            "what_it_looks_for": "A HIGH password reset request",
            "severity": "High",
            "data": "factory_security_logs.csv",
        },
    ]
)


def empty_alerts() -> pd.DataFrame:
    """A correctly shaped, empty alert table."""
    return pd.DataFrame(columns=ALERT_COLUMNS)


def _clock(value) -> str:
    """Format a timestamp as HH:MM for compact evidence text."""
    return pd.Timestamp(value).strftime("%H:%M")


def _record(
    *,
    time: str,
    severity: str,
    rule_id: str,
    rule: str,
    entity: str,
    evidence: str,
    action: str,
    source: str,
) -> dict:
    return {
        "time": time,
        "severity": severity,
        "rule_id": rule_id,
        "rule": rule,
        "entity": entity,
        "evidence": evidence,
        "action": action,
        "source": source,
    }


# --------------------------------------------------------------------- rules
def repeated_failed_logins(logins: pd.DataFrame) -> pd.DataFrame:
    """R1: flag users with three or more failed logins in the simple log."""
    failed = logins[logins["result"] == "failed"]
    if failed.empty:
        return empty_alerts()

    summary = (
        failed.groupby("user")
        .agg(
            attempts=("result", "size"),
            last_attempt=("timestamp", "max"),
            devices=("device", lambda values: ", ".join(sorted(set(values)))),
            locations=("location", lambda values: ", ".join(sorted(set(values)))),
        )
        .reset_index()
    )
    summary = summary[summary["attempts"] >= FAILED_LOGIN_THRESHOLD]

    records = []
    for row in summary.itertuples():
        severity = "High" if row.attempts >= HIGH_FAILED_LOGIN_THRESHOLD else "Medium"
        records.append(
            _record(
                time=_clock(row.last_attempt),
                severity=severity,
                rule_id="R1",
                rule="Repeated failed logins",
                entity=row.user,
                evidence=(
                    f"{row.attempts} failed logins for {row.user} on {row.devices} "
                    f"from {row.locations}; last attempt at {_clock(row.last_attempt)}."
                ),
                action="Confirm with the user, then reset the password and review the device.",
                source="login_logs.csv",
            )
        )
    return pd.DataFrame(records, columns=RULE_COLUMNS)


def network_risk(network: pd.DataFrame) -> pd.DataFrame:
    """R2: summarise suspicious or very large transfers per device."""
    flagged = network[network["flagged"]]
    if flagged.empty:
        return empty_alerts()

    summary = (
        flagged.groupby("device")
        .agg(
            suspicious=("category", lambda values: int((values == "suspicious").sum())),
            large=("large_transfer", "sum"),
            total_bytes=("bytes_sent", "sum"),
            destinations=("destination", lambda values: ", ".join(sorted(set(values)))),
        )
        .reset_index()
    )

    records = []
    for row in summary.itertuples():
        severity = "High" if row.suspicious >= 3 or row.total_bytes > 300_000 else "Medium"
        kilobytes = row.total_bytes / 1000
        if row.suspicious:
            evidence = (
                f"{row.suspicious} suspicious transfer(s) from {row.device} to "
                f"{row.destinations}, sending about {kilobytes:,.0f} KB in total."
            )
        else:
            evidence = (
                f"{row.device} sent about {kilobytes:,.0f} KB to {row.destinations}. "
                "The destination looks normal, so this may be a large but legitimate transfer."
            )
        records.append(
            _record(
                time="--:--",
                severity=severity,
                rule_id="R2",
                rule="Risky network traffic",
                entity=row.device,
                evidence=evidence,
                action="Confirm the destination with the user, then block it if it is not approved.",
                source="network_logs.csv",
            )
        )
    return pd.DataFrame(records, columns=RULE_COLUMNS)


def login_bursts(factory: pd.DataFrame) -> pd.DataFrame:
    """R3: look for a cluster of failures inside a short time window."""
    failed = factory[factory["event_type"] == "LOGIN_FAILED"]
    if failed.empty:
        return empty_alerts()

    records = []
    for (user, ip), group in failed.groupby(["username", "ip_address"]):
        times = sorted(group["timestamp"].tolist())
        best_window: list[pd.Timestamp] = []
        for moment in times:
            window = [
                value
                for value in times
                if moment - timedelta(minutes=LOGIN_WINDOW_MINUTES) <= value <= moment
            ]
            if len(window) > len(best_window):
                best_window = window

        if len(best_window) < FAILED_LOGIN_THRESHOLD:
            continue

        window_start, window_end = best_window[0], best_window[-1]
        successes = factory[
            (factory["username"] == user)
            & (factory["ip_address"] == ip)
            & (factory["event_type"] == "LOGIN_SUCCESS")
            & (factory["timestamp"] >= window_start)
            & (factory["timestamp"] <= window_end + timedelta(minutes=15))
        ]

        severity = "High" if len(best_window) >= HIGH_FAILED_LOGIN_THRESHOLD else "Medium"
        evidence = (
            f"{len(best_window)} failed logins for {user} from {ip} between "
            f"{_clock(window_start)} and {_clock(window_end)}"
        )
        if not successes.empty:
            evidence += f", followed by a successful login at {_clock(successes.iloc[0]['timestamp'])}."
        else:
            evidence += " with no successful login."

        records.append(
            _record(
                time=_clock(window_end),
                severity=severity,
                rule_id="R3",
                rule="Login burst in a short window",
                entity=f"{user} @ {ip}",
                evidence=evidence,
                action="Check with the account owner and require a password reset if the burst is not explained.",
                source="factory_security_logs.csv",
            )
        )
    return pd.DataFrame(records, columns=RULE_COLUMNS)


def critical_events(factory: pd.DataFrame) -> pd.DataFrame:
    """R4: every row already marked CRITICAL gets its own alert."""
    critical = factory[factory["severity"] == "Critical"]
    records = [
        _record(
            time=_clock(row.timestamp),
            severity="Critical",
            rule_id="R4",
            rule="Critical event recorded",
            entity=row.username,
            evidence=f"{row.event_type} on {row.device} ({row.ip_address}): {row.details}.",
            action="Escalate to the facilitator or duty manager and preserve the log rows as evidence.",
            source="factory_security_logs.csv",
        )
        for row in critical.itertuples()
    ]
    return pd.DataFrame(records, columns=RULE_COLUMNS)


def removable_media(factory: pd.DataFrame) -> pd.DataFrame:
    """R5: USB drives on servers, and files opened from removable media."""
    records = []

    server_usb = factory[
        (factory["event_type"] == "USB_INSERTED")
        & (factory["device"].str.startswith("server"))
    ]
    if not server_usb.empty:
        devices = ", ".join(sorted(set(server_usb["device"])))
        records.append(
            _record(
                time=_clock(server_usb["timestamp"].max()),
                severity="High",
                rule_id="R5",
                rule="Risky removable media",
                entity=devices,
                evidence=(
                    f"{len(server_usb)} removable drive event(s) on {devices}. "
                    "Servers should not accept unknown USB storage."
                ),
                action="Remove the device, scan it offline, and apply the USB policy.",
                source="factory_security_logs.csv",
            )
        )

    risky_files = factory[
        (factory["event_type"] == "FILE_OPEN")
        & (
            factory["details"].str.contains("removable", case=False, na=False)
            | factory["details"].str.contains("unknown_invoice", case=False, na=False)
        )
    ]
    for row in risky_files.itertuples():
        records.append(
            _record(
                time=_clock(row.timestamp),
                severity="High",
                rule_id="R5",
                rule="Risky removable media",
                entity=f"{row.username} on {row.device}",
                evidence=f"{row.details} (source {row.ip_address}).",
                action="Quarantine the file and check the device with an approved antivirus scan.",
                source="factory_security_logs.csv",
            )
        )

    return pd.DataFrame(records, columns=RULE_COLUMNS)


def password_resets(factory: pd.DataFrame) -> pd.DataFrame:
    """R6: high-severity password resets, for example from an unusual address."""
    resets = factory[
        (factory["event_type"] == "PASSWORD_RESET") & (factory["severity"] == "High")
    ]
    records = [
        _record(
            time=_clock(row.timestamp),
            severity="High",
            rule_id="R6",
            rule="Password reset from an unusual address",
            entity=row.username,
            evidence=f"{row.details} from {row.ip_address} on {row.device}.",
            action="Verify the request with the user through a known channel before allowing the reset.",
            source="factory_security_logs.csv",
        )
        for row in resets.itertuples()
    ]
    return pd.DataFrame(records, columns=RULE_COLUMNS)


# ------------------------------------------------------------------ assembly
def combine_alerts(*tables: pd.DataFrame) -> pd.DataFrame:
    """Merge alert tables, assign readable IDs, and sort by severity."""
    frames = [table for table in tables if table is not None and not table.empty]
    if not frames:
        return empty_alerts()

    alerts = pd.concat(frames, ignore_index=True)
    if "alert_id" in alerts.columns:
        alerts = alerts.drop(columns="alert_id")
    rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    alerts["_rank"] = alerts["severity"].map(rank)
    alerts = alerts.sort_values(["_rank", "time"], ascending=[True, False]).drop(
        columns="_rank"
    )
    alerts.insert(0, "alert_id", [f"ALT-{number:03d}" for number in range(1, len(alerts) + 1)])
    return alerts[ALERT_COLUMNS].reset_index(drop=True)


def simple_alerts(logins: pd.DataFrame, network: pd.DataFrame) -> pd.DataFrame:
    """Alerts that come from the two small starter datasets."""
    return combine_alerts(repeated_failed_logins(logins), network_risk(network))


def investigation_alerts(factory: pd.DataFrame) -> pd.DataFrame:
    """Alerts that come from the combined factory security log."""
    return combine_alerts(
        login_bursts(factory),
        critical_events(factory),
        removable_media(factory),
        password_resets(factory),
    )


def severity_counts(alerts: pd.DataFrame) -> pd.DataFrame:
    """Count alerts per severity in a fixed, meaningful order."""
    counts = alerts["severity"].value_counts()
    return pd.DataFrame(
        {
            "severity": SEVERITY_ORDER,
            "alerts": [int(counts.get(severity, 0)) for severity in SEVERITY_ORDER],
        }
    )


def risk_score(alerts: pd.DataFrame) -> dict:
    """Turn the alert list into a simple 0-100 teaching score."""
    counts = alerts["severity"].value_counts().to_dict()
    raw = sum(SEVERITY_WEIGHTS.get(severity, 0) * count for severity, count in counts.items())
    score = min(100, int(raw))

    band, colour, message = RISK_BANDS[-1][1], RISK_BANDS[-1][2], RISK_BANDS[-1][3]
    for threshold, label, colour_value, guidance in RISK_BANDS:
        if score >= threshold:
            band, colour, message = label, colour_value, guidance
            break

    return {
        "score": score,
        "band": band,
        "colour": colour,
        "message": message,
        "counts": {severity: int(counts.get(severity, 0)) for severity in SEVERITY_ORDER},
        "total": int(len(alerts)),
    }


def recommendations(alerts: pd.DataFrame) -> list[dict[str, str]]:
    """Plain-language defensive actions linked to the rules that fired."""
    rules = set(alerts["rule_id"])
    actions: list[dict[str, str]] = []

    if "R4" in rules:
        actions.append(
            {
                "priority": "1",
                "title": "Contain the admin account and review the export",
                "detail": (
                    "Disable the admin account, force a password reset, and check whether "
                    "staff_list.csv left the network. Preserve the 09:10-09:17 log rows."
                ),
            }
        )
    if "R3" in rules:
        actions.append(
            {
                "priority": "2",
                "title": "Add lockout and multi-factor authentication",
                "detail": (
                    "Lock an account after three failed attempts in ten minutes and require a "
                    "second factor for admin and remote logins."
                ),
            }
        )
    if "R5" in rules:
        actions.append(
            {
                "priority": "3",
                "title": "Enforce the removable-media policy",
                "detail": (
                    "Block unknown USB storage on servers and reception devices, and scan any "
                    "drive before it is used."
                ),
            }
        )
    if "R6" in rules:
        actions.append(
            {
                "priority": "4",
                "title": "Verify password resets through a known channel",
                "detail": (
                    "Never approve a reset from a message alone. Call the user back on the "
                    "number already on record."
                ),
            }
        )
    if "R1" in rules or "R2" in rules:
        actions.append(
            {
                "priority": "5",
                "title": "Fix the two starter-log findings",
                "detail": (
                    "Review the guest and maya accounts, and block the unknown-site destination "
                    "used by laptop-04."
                ),
            }
        )

    actions.append(
        {
            "priority": str(len(actions) + 1),
            "title": "Keep the routine checks running",
            "detail": (
                "Review this dashboard at the start of each shift, export the alert table, and "
                "add new detection rules when the logs change."
            ),
        }
    )
    return actions
