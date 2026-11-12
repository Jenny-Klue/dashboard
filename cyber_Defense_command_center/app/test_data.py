# -*- coding: utf-8 -*-
"""Sanity check: can Python open the practice CSV files?

Run from the project folder:  python app/test_data.py
"""

from data_loader import load_all

bundle = load_all()

print("NovaTech practice data")
print("=" * 40)
for name, frame in (
    ("login_logs.csv", bundle.logins),
    ("network_logs.csv", bundle.network),
    ("messages.csv", bundle.messages),
    ("factory_security_logs.csv", bundle.factory),
):
    print(f"{name:<28} {len(frame):>4} rows, {len(frame.columns)} columns")

print("\nFirst login rows:")
print(bundle.logins[["time", "user", "device", "result", "location"]].head().to_string(index=False))

print("\nData quality summary:")
print(bundle.quality["result"].value_counts().to_string())
