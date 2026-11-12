# -*- coding: utf-8 -*-
"""Load, clean, and enrich the toy security logs.

Every column is documented here because the Data Detective badge asks you to
explain what each one means:

login_logs.csv      time, user, device, result, location
network_logs.csv    time, device, destination, bytes_sent, category
messages.csv        id, message, label, reason
factory_security_logs.csv
                    timestamp, username, ip_address, device,
                    event_type, severity, details
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from config import DATA_DIR, LARGE_TRANSFER_BYTES

# The toy logs are all from one practice day. We attach it so charts can plot
# real timestamps even though login_logs.csv only stores a clock time.
PRACTICE_DATE = "2026-02-03"


@dataclass
class DataBundle:
    """All four toy tables plus a small data-quality report."""

    logins: pd.DataFrame
    network: pd.DataFrame
    messages: pd.DataFrame
    factory: pd.DataFrame
    quality: pd.DataFrame


def _read_csv(file_name: str) -> pd.DataFrame:
    """Read one CSV, tidy the headers, and strip stray spaces from text."""
    path = DATA_DIR / file_name
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path}. Check that the data folder sits next to app/."
        )

    frame = pd.read_csv(path)
    frame.columns = [column.strip().lower() for column in frame.columns]

    for column in frame.columns:
        if pd.api.types.is_string_dtype(frame[column]):
            frame[column] = frame[column].astype(str).str.strip()
    return frame


def load_logins() -> pd.DataFrame:
    logins = _read_csv("login_logs.csv")
    logins["result"] = logins["result"].str.lower()
    logins["location"] = logins["location"].str.lower()
    logins["timestamp"] = pd.to_datetime(
        PRACTICE_DATE + " " + logins["time"], format="%Y-%m-%d %H:%M", errors="coerce"
    )
    logins["outside_location"] = logins["location"] != "local"
    logins["failed"] = logins["result"] == "failed"
    return logins


def load_network() -> pd.DataFrame:
    network = _read_csv("network_logs.csv")
    network["bytes_sent"] = pd.to_numeric(network["bytes_sent"], errors="coerce").fillna(0).astype(int)
    network["category"] = network["category"].str.lower()
    network["destination"] = network["destination"].str.lower()
    network["timestamp"] = pd.to_datetime(
        PRACTICE_DATE + " " + network["time"], format="%Y-%m-%d %H:%M", errors="coerce"
    )
    network["large_transfer"] = network["bytes_sent"] > LARGE_TRANSFER_BYTES
    network["flagged"] = (network["category"] == "suspicious") | network["large_transfer"]
    return network


def load_messages() -> pd.DataFrame:
    messages = _read_csv("messages.csv")
    messages["label"] = messages["label"].str.lower()
    return messages


def load_factory() -> pd.DataFrame:
    factory = _read_csv("factory_security_logs.csv")
    factory["timestamp"] = pd.to_datetime(factory["timestamp"], errors="coerce")
    factory = factory.dropna(subset=["timestamp"]).sort_values("timestamp")
    factory["severity"] = factory["severity"].str.title()
    factory["hour"] = factory["timestamp"].dt.hour
    factory["after_hours"] = (factory["hour"] < 8) | (factory["hour"] >= 17)
    return factory.reset_index(drop=True)


def quality_report(bundle_parts: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Build a short 'can I trust this data?' table for the dashboard."""
    checks: list[dict[str, str]] = []

    for name, frame in bundle_parts.items():
        duplicates = int(frame.duplicated().sum())
        missing = int(frame.isna().sum().sum())
        checks.append(
            {
                "check": f"{name} loaded",
                "result": "Pass" if len(frame) > 0 else "Fail",
                "detail": f"{len(frame)} rows, {len(frame.columns)} columns",
            }
        )
        checks.append(
            {
                "check": f"{name} duplicates",
                "result": "Pass" if duplicates == 0 else "Review",
                "detail": f"{duplicates} duplicate row(s)",
            }
        )
        checks.append(
            {
                "check": f"{name} missing values",
                "result": "Pass" if missing == 0 else "Review",
                "detail": f"{missing} empty cell(s)",
            }
        )

    return pd.DataFrame(checks)


def load_all() -> DataBundle:
    """Load and clean every toy file in one call."""
    logins = load_logins()
    network = load_network()
    messages = load_messages()
    factory = load_factory()

    quality = quality_report(
        {
            "login_logs.csv": logins,
            "network_logs.csv": network,
            "messages.csv": messages,
            "factory_security_logs.csv": factory,
        }
    )
    return DataBundle(logins, network, messages, factory, quality)
