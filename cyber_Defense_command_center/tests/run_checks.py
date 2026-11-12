# -*- coding: utf-8 -*-
"""Automated test plan for the command centre.

Run from the project folder:

    python tests/run_checks.py

No pytest required. Each check prints PASS or FAIL and the command exits with
code 1 if anything breaks, which makes it easy to add to a portfolio.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "app"))

import classifier
import data_loader
import detections
import report_builder

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(condition), detail))


def main() -> int:
    bundle = data_loader.load_all()

    # ---------------------------------------------------------- data files
    expected = {
        "login_logs.csv": (bundle.logins, 45),
        "network_logs.csv": (bundle.network, 28),
        "messages.csv": (bundle.messages, 43),
        "factory_security_logs.csv": (bundle.factory, 140),
    }
    for file_name, (frame, minimum) in expected.items():
        check(f"{file_name} loads with enough rows", len(frame) >= minimum, f"{len(frame)} rows")

    check(
        "login log columns are the expected five",
        {"time", "user", "device", "result", "location"}.issubset(bundle.logins.columns),
        ", ".join(bundle.logins.columns),
    )
    check(
        "no duplicate rows in the factory log",
        int(bundle.factory.duplicated().sum()) == 0,
        f"{int(bundle.factory.duplicated().sum())} duplicates",
    )
    check(
        "timestamps parsed for every factory row",
        bundle.factory["timestamp"].notna().all(),
        f"{int(bundle.factory['timestamp'].isna().sum())} unparsed",
    )

    # ------------------------------------------------------------ detection
    starter = detections.simple_alerts(bundle.logins, bundle.network)
    check("R1 flags guest with a High alert", "guest" in set(starter["entity"]), f"{len(starter)} starter alerts")
    check("R1 flags maya", "maya" in set(starter["entity"]))
    check("R2 flags laptop-04", "laptop-04" in set(starter["entity"]))
    check(
        "starter alert severities are valid",
        set(starter["severity"]).issubset(set(detections.SEVERITY_ORDER)),
        ", ".join(sorted(set(starter["severity"]))),
    )

    factory_alerts = detections.investigation_alerts(bundle.factory)
    rules = set(factory_alerts["rule_id"])
    check("R3 login burst fires", "R3" in rules)
    check("R4 critical events fire", "R4" in rules)
    check("R5 removable media fires", "R5" in rules)
    check("R6 password reset fires", "R6" in rules)
    check(
        "admin chain is critical",
        int(
            (
                (factory_alerts["entity"] == "admin")
                & (factory_alerts["severity"] == "Critical")
            ).sum()
        )
        == 2,
        "expected 2 admin critical alerts",
    )

    risk = detections.risk_score(factory_alerts)
    check("risk score is between 0 and 100", 0 <= risk["score"] <= 100, f"{risk['score']}/100")
    check("risk band is High for this data", risk["band"] == "High", risk["band"])
    check("recommendations exist", len(detections.recommendations(factory_alerts)) >= 4)

    # ----------------------------------------------------------- classifier
    vectorizer, model = classifier.train(bundle.messages)
    phishing = classifier.predict_message(
        vectorizer, model, "urgent password reset required"
    )
    normal = classifier.predict_message(vectorizer, model, "team meeting at 11")
    unknown = classifier.predict_message(vectorizer, model, "qwerty zzz")

    check("classifier marks the phishing example suspicious", phishing["label"] == "suspicious",
          f"{phishing['label']} ({phishing['confidence']:.0%})")
    check("classifier marks the meeting example safe", normal["label"] == "safe",
          f"{normal['label']} ({normal['confidence']:.0%})")
    check("classifier admits an unknown message", unknown["unknown"] is True)
    accuracy = classifier.cross_validated_accuracy(bundle.messages)
    check("cross-validated accuracy is above 70%", bool(accuracy and accuracy > 0.70),
          f"{accuracy:.0%}" if accuracy else "n/a")

    # --------------------------------------------------------------- report
    report = report_builder.build_markdown()
    required_sections = [
        "## 1. Executive summary",
        "## 3. Key findings",
        "## 4. Risk level",
        "## 5. Recommended actions",
        "## 7. Screenshots",
        "## 8. Reflection",
    ]
    check(
        "report has all required sections",
        all(section in report for section in required_sections),
        f"{len(report):,} characters",
    )
    check("report includes the admin finding", "203.0.113.45" in report)
    check("report uses toy-log safety wording", "fictional practice logs" in report.lower())

    # --------------------------------------------------------------- output
    width = max(len(name) for name, _, _ in RESULTS)
    failures = 0
    print("\nNovaTech Blue Team - automated checks")
    print("=" * (width + 12))
    for name, passed, detail in RESULTS:
        status = "PASS" if passed else "FAIL"
        if not passed:
            failures += 1
        print(f"[{status}] {name.ljust(width)}  {detail}")
    print("=" * (width + 12))
    print(f"{len(RESULTS) - failures}/{len(RESULTS)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
