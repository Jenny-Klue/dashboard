# -*- coding: utf-8 -*-
"""NovaTech Blue Team project settings.

Everything a learner is likely to personalise lives here, so the rest of the
code can stay untouched. Change the names and thresholds and the dashboard
updates everywhere.
"""

from pathlib import Path

# --------------------------------------------------------------------- folders
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
SCREENSHOTS_DIR = BASE_DIR / "screenshots"

# ------------------------------------------------------------------ branding
TEAM_NAME = "Odin FIT team"
PROJECT_NAME = "Cyber Defence Command Centre"
ANALYST_NAME = "Jennifer"
SHIFT_LABEL = "Shift A  |  08:00 - 16:00  |  03 Feb 2026"
FACILITY = "Odin FIT Smart Factory"

# ------------------------------------------------------------------ rule settings
FAILED_LOGIN_THRESHOLD = 3       # 3 failures for one user raises an alert
HIGH_FAILED_LOGIN_THRESHOLD = 4  # 4 or more is treated as high severity
LARGE_TRANSFER_BYTES = 50_000    # anything bigger than 50 KB is worth a look
LOGIN_WINDOW_MINUTES = 10        # burst window used on the combined log
BUSINESS_HOURS = (8, 17)         # events outside these hours are marked after-hours

# -------------------------------------------------------------- severities
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = {"Critical": 20, "High": 8, "Medium": 3, "Low": 1}
SEVERITY_COLORS = {
    "Critical": "#ff4d6d",
    "High": "#ff8f4d",
    "Medium": "#ffd166",
    "Low": "#39d98a",
}

RISK_BANDS = [
    (80, "High", "#ff4d6d", "Act now. A serious event needs containment today."),
    (50, "Elevated", "#ff9f43", "Investigate today and tighten the weak controls."),
    (20, "Moderate", "#ffd166", "Keep monitoring. Fix the small issues before they grow."),
    (0, "Guarded", "#39d98a", "No major pattern found. Keep the routine checks running."),
]

# Accent colours used by the custom CSS and the charts.
ACCENT = "#5ab0ff"
ACCENT_SOFT = "#1c3f63"
SURFACE = "#101826"
