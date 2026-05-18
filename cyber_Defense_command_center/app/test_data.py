import pandas as pd
logins = pd.read_csv("data/login_logs.csv")
print(logins.head())
print("Rows:", len(logins))