# -*- coding: utf-8 -*-
"""Print the login and network alerts from the starter logs.

Run from the project folder:  python app/detect_logins.py
"""

import pandas as pd

from data_loader import load_logins, load_network
from detections import network_risk, repeated_failed_logins

pd.set_option("display.width", 160)
pd.set_option("display.max_colwidth", 70)

logins = load_logins()
network = load_network()

print("Repeated failed logins (rule R1)")
print("=" * 80)
print(
    repeated_failed_logins(logins)[
        ["time", "severity", "entity", "evidence", "action"]
    ].to_string(index=False)
)

print("\nRisky network traffic (rule R2)")
print("=" * 80)
print(
    network_risk(network)[
        ["time", "severity", "entity", "evidence", "action"]
    ].to_string(index=False)
)
