import pandas as pd
logins = pd.read_csv("data/login_logs.csv")
failed = logins[logins["result"] == "failed"]
counts = failed.groupby("user").size().reset_index(name="failed_attempts")
counts["alert"] = counts["failed_attempts"] >= 3
print(counts)