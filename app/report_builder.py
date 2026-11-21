# -*- coding: utf-8 -*-
"""Build the Odin Fit incident report from the detection results.

The dashboard and the command line both use these functions, so the report on
screen, the downloadable copy, and reports/Incident_Report.md stay in sync.

Run `python app/report_builder.py` from the project folder to refresh the file.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from classifier import cross_validated_accuracy
from config import (
    ANALYST_NAME,
    DATA_DIR,
    FACILITY,
    PROJECT_NAME,
    REPORTS_DIR,
    SHIFT_LABEL,
    TEAM_NAME,
)
from data_loader import DataBundle, load_all
from detections import (
    investigation_alerts,
    recommendations,
    risk_score,
    severity_counts,
    simple_alerts,
)

SCREENSHOT_FILES = [
    "command-centre.png",
    "investigation.png",
    "message-checker.png",
    "incident-report.png",
]


def build_context(bundle: DataBundle | None = None) -> dict:
    """Collect every number and table the report needs."""
    bundle = bundle or load_all()
    factory_alerts = investigation_alerts(bundle.factory)
    starter_alerts = simple_alerts(bundle.logins, bundle.network)

    return {
        "bundle": bundle,
        "factory_alerts": factory_alerts,
        "starter_alerts": starter_alerts,
        "risk": risk_score(factory_alerts),
        "severity": severity_counts(factory_alerts),
        "recommendations": recommendations(factory_alerts),
    }


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Small Markdown table helper so we do not need the tabulate package."""
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        cleaned = [str(value).replace("|", "/").replace("\n", " ") for value in row]
        lines.append("| " + " | ".join(cleaned) + " |")
    return "\n".join(lines)


def _alert_rows(alerts: pd.DataFrame) -> list[list[str]]:
    return [
        [row.alert_id, row.time, row.severity, row.rule, row.entity, row.evidence]
        for row in alerts.itertuples()
    ]


def executive_summary(context: dict) -> str:
    """One short paragraph a busy manager can read first."""
    risk = context["risk"]
    bundle = context["bundle"]
    critical = risk["counts"]["Critical"]
    high = risk["counts"]["High"]

    return (
        f"On {SHIFT_LABEL.split('|')[-1].strip()}, the {TEAM_NAME} reviewed "
        f"{len(bundle.factory)} factory security events, {len(bundle.logins)} login events, "
        f"{len(bundle.network)} network events, and {len(bundle.messages)} practice messages. "
        f"The rules raised {risk['total']} alerts, including {critical} critical and {high} high "
        f"severity events. The most serious finding is the admin account: four failed logins from "
        f"the outside address 203.0.113.45 were followed by a successful login and the download of "
        f"staff_list.csv between 09:10 and 09:17. Guest and helper accounts also produced repeated "
        f"failure bursts, and laptop-04 sent about 718 KB to an unknown site. The overall risk score "
        f"is {risk['score']}/100 ({risk['band']}). The admin session should be contained first, then "
        f"lockout, multi-factor authentication, and USB controls should be tightened."
    )


def key_findings(context: dict) -> list[str]:
    """Numbered findings, written the way a junior analyst would explain them."""
    days = "03 Feb 2026"
    return [
        (
            f"**Admin account compromise (Critical).** Four failed logins for `admin` came from "
            f"`203.0.113.45` between 09:10 and 09:13, followed by a successful login at 09:15 and a "
            f"download of `staff_list.csv` at 09:17. This matches the classic pattern of password "
            f"guessing and then using the account. Evidence: ALT-007, ALT-002, ALT-001."
        ),
        (
            f"**Guest login burst (High).** `guest` failed five times from `10.0.0.41` on "
            f"`quality-tablet` between 11:02 and 11:07, then logged in successfully at 11:08. The "
            f"account may be shared or the password may be written down nearby. Evidence: ALT-006."
        ),
        (
            f"**Helper account and laptop-04 (High).** In the starter logs, `guest` failed seven "
            f"times from an unknown location and `maya` failed four times. The same device marked "
            f"`laptop-04` sent eight suspicious transfers (about 718 KB) to `unknown-site`. "
            f"Evidence: starter alerts ALT-001 to ALT-003."
        ),
        (
            f"**Removable media risk (High).** A visitor connected an unknown USB drive to the "
            f"reception laptop at 12:40 and opened `unknown_invoice.txt` at 12:42. A removable drive "
            f"was also seen on `server-01` at 14:32. Evidence: ALT-005, ALT-003."
        ),
        (
            f"**Unusual password reset (High).** `operator01` requested a password reset from "
            f"`198.51.100.23` at 14:05, an address that does not look like the normal factory range. "
            f"Evidence: ALT-004."
        ),
        (
            f"**Likely false positive (Medium).** `thabo` failed three times at 09:05-09:07 and then "
            f"succeeded, which looks like ordinary typing mistakes. `laptop-01` also sent 86 KB to "
            f"`video-call`, a large but normal destination. Both stay in the report as examples of "
            f"why an alert is a clue, not proof."
        ),
    ]


def evidence_reviewed() -> list[str]:
    return [
        "`data/factory_security_logs.csv` - 149 combined events (the main investigation).",
        "`data/login_logs.csv` - 46 login events with user, device, result, and location.",
        "`data/network_logs.csv` - 29 transfers with destination, size, and category.",
        "`data/messages.csv` - 44 labelled messages used to train and check the classifier.",
        "Dashboard pages: Command Centre, Investigation, Message Checker, and Incident Report.",
        "Detection rules R1-R6 in `app/detections.py` and the colour-coded alert table.",
    ]


def reflection(context: dict) -> list[str]:
    return [
        (
            "I learned that a security alert is only the start of the work. The admin alert became "
            "useful when I put the failed logins, the successful login, and the file download in "
            "time order and could explain the chain."
        ),
        (
            "The hardest part was deciding the thresholds. Three failures is strict enough to catch "
            "a burst but noisy enough to catch typing mistakes, which is why the thabo case stayed "
            "Medium and is labelled as probably harmless."
        ),
        (
            "The message classifier reached about "
            f"{cross_validated_accuracy(context['bundle'].messages) or 0:.0%} cross-validated accuracy "
            "on only 44 messages. That is fine for practice, but it shows why a model should support "
            "a human decision instead of replacing one."
        ),
        (
            "Next time I would add a proper time range filter, export the evidence to a signed PDF, "
            "and test the rules against a second day of toy logs to see how many false positives they "
            "create."
        ),
    ]


def build_markdown(context: dict | None = None, notes: str = "") -> str:
    """Return the complete incident report as Markdown."""
    context = context or build_context()
    risk = context["risk"]
    severity_rows = [
        [row.severity, str(row.alerts)] for row in context["severity"].itertuples()
    ]

    sections: list[str] = []
    sections.append("# FIT Cyber Incident Report")
    sections.append("")
    sections.append(f"**Facility:** {FACILITY}  ")
    sections.append(f"**Project:** {PROJECT_NAME}  ")
    sections.append(f"**Team:** {TEAM_NAME}  ")
    sections.append(f"**Analyst:** {ANALYST_NAME}  ")
    sections.append(f"**Shift:** {SHIFT_LABEL}  ")
    sections.append("**Data:** Fictional practice logs only. No real system was tested.")
    sections.append("")

    sections.append("## 1. Executive summary")
    sections.append("")
    sections.append(executive_summary(context))
    sections.append("")

    sections.append("## 2. Evidence reviewed")
    sections.append("")
    sections.extend(f"- {item}" for item in evidence_reviewed())
    sections.append("")

    sections.append("## 3. Key findings")
    sections.append("")
    sections.extend(f"{number}. {finding}" for number, finding in enumerate(key_findings(context), start=1))
    sections.append("")

    sections.append("## 4. Risk level")
    sections.append("")
    sections.append(
        f"**{risk['band'].upper()} - {risk['score']}/100.** {risk['message']}"
    )
    sections.append("")
    sections.append(
        "The score adds weighted alert counts: Critical = 20 points, High = 8, Medium = 3, "
        "Low = 1, capped at 100. It is a teaching score, not a scientific measurement."
    )
    sections.append("")
    sections.append(_md_table(["Severity", "Alerts"], severity_rows))
    sections.append("")

    sections.append("## 5. Recommended actions")
    sections.append("")
    for action in context["recommendations"]:
        sections.append(f"{action['priority']}. **{action['title']}** - {action['detail']}")
    sections.append("")

    sections.append("## 6. Alert evidence")
    sections.append("")
    sections.append(_md_table(
        ["ID", "Time", "Severity", "Rule", "Entity", "Evidence"],
        _alert_rows(context["factory_alerts"]),
    ))
    sections.append("")
    sections.append("Starter-log alerts are shown on the Command Centre page and are summarised in finding 3.")
    sections.append("")

    sections.append("## 7. Screenshots")
    sections.append("")
    sections.extend(f"- `screenshots/{name}`" for name in SCREENSHOT_FILES)
    sections.append("")

    sections.append("## 8. Reflection")
    sections.append("")
    sections.extend(f"- {item}" for item in reflection(context))
    sections.append("")

    if notes.strip():
        sections.append("## 9. Analyst notes")
        sections.append("")
        sections.append(notes.strip())
        sections.append("")

    sections.append("---")
    sections.append("")
    sections.append(
        "Safe lab statement: this investigation used only the toy CSV files in this project. "
        "No real network, account, website, or person was scanned or tested."
    )
    sections.append("")
    return "\n".join(sections)


def write_report(path: Path | None = None, notes: str = "") -> Path:
    """Generate the report file and return where it was written."""
    path = path or REPORTS_DIR / "Incident_Report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_markdown(notes=notes), encoding="utf-8")
    return path


if __name__ == "__main__":
    written = write_report()
    print(f"Incident report written to {written}")
    print(f"Toy data folder: {DATA_DIR}")
