# FIT Cyber Incident Report

**Facility:** Odin Fit Smart Factory  
**Project:** Cyber Defence Command Centre  
**Team:** Odin Fit team  
**Analyst:** Jennifer  
**Shift:** Shift A  |  08:00 - 16:00  |  03 Feb 2026  
**Data:** Fictional practice logs only. No real system was tested.

## 1. Executive summary

On 03 Feb 2026, the Odin Fit team reviewed 149 factory security events, 46 login events, 29 network events, and 44 practice messages. The rules raised 8 alerts, including 2 critical and 5 high severity events. The most serious finding is the admin account: four failed logins from the outside address 203.0.113.45 were followed by a successful login and the download of staff_list.csv between 09:10 and 09:17. Guest and helper accounts also produced repeated failure bursts, and laptop-04 sent about 718 KB to an unknown site. The overall risk score is 83/100 (High). The admin session should be contained first, then lockout, multi-factor authentication, and USB controls should be tightened.

## 2. Evidence reviewed

- `data/factory_security_logs.csv` - 149 combined events (the main investigation).
- `data/login_logs.csv` - 46 login events with user, device, result, and location.
- `data/network_logs.csv` - 29 transfers with destination, size, and category.
- `data/messages.csv` - 44 labelled messages used to train and check the classifier.
- Dashboard pages: Command Centre, Investigation, Message Checker, and Incident Report.
- Detection rules R1-R6 in `app/detections.py` and the colour-coded alert table.

## 3. Key findings

1. **Admin account compromise (Critical).** Four failed logins for `admin` came from `203.0.113.45` between 09:10 and 09:13, followed by a successful login at 09:15 and a download of `staff_list.csv` at 09:17. This matches the classic pattern of password guessing and then using the account. Evidence: ALT-007, ALT-002, ALT-001.
2. **Guest login burst (High).** `guest` failed five times from `10.0.0.41` on `quality-tablet` between 11:02 and 11:07, then logged in successfully at 11:08. The account may be shared or the password may be written down nearby. Evidence: ALT-006.
3. **Helper account and laptop-04 (High).** In the starter logs, `guest` failed seven times from an unknown location and `maya` failed four times. The same device marked `laptop-04` sent eight suspicious transfers (about 718 KB) to `unknown-site`. Evidence: starter alerts ALT-001 to ALT-003.
4. **Removable media risk (High).** A visitor connected an unknown USB drive to the reception laptop at 12:40 and opened `unknown_invoice.txt` at 12:42. A removable drive was also seen on `server-01` at 14:32. Evidence: ALT-005, ALT-003.
5. **Unusual password reset (High).** `operator01` requested a password reset from `198.51.100.23` at 14:05, an address that does not look like the normal factory range. Evidence: ALT-004.
6. **Likely false positive (Medium).** `thabo` failed three times at 09:05-09:07 and then succeeded, which looks like ordinary typing mistakes. `laptop-01` also sent 86 KB to `video-call`, a large but normal destination. Both stay in the report as examples of why an alert is a clue, not proof.

## 4. Risk level

**HIGH - 83/100.** Act now. A serious event needs containment today.

The score adds weighted alert counts: Critical = 20 points, High = 8, Medium = 3, Low = 1, capped at 100. It is a teaching score, not a scientific measurement.

| Severity | Alerts |
|---|---|
| Critical | 2 |
| High | 5 |
| Medium | 1 |
| Low | 0 |

## 5. Recommended actions

1. **Contain the admin account and review the export** - Disable the admin account, force a password reset, and check whether staff_list.csv left the network. Preserve the 09:10-09:17 log rows.
2. **Add lockout and multi-factor authentication** - Lock an account after three failed attempts in ten minutes and require a second factor for admin and remote logins.
3. **Enforce the removable-media policy** - Block unknown USB storage on servers and reception devices, and scan any drive before it is used.
4. **Verify password resets through a known channel** - Never approve a reset from a message alone. Call the user back on the number already on record.
5. **Keep the routine checks running** - Review this dashboard at the start of each shift, export the alert table, and add new detection rules when the logs change.

## 6. Alert evidence

| ID | Time | Severity | Rule | Entity | Evidence |
|---|---|---|---|---|---|
| ALT-001 | 09:17 | Critical | Critical event recorded | admin | FILE_DOWNLOAD on server-01 (203.0.113.45): downloaded staff_list.csv after suspicious login. |
| ALT-002 | 09:15 | Critical | Critical event recorded | admin | LOGIN_SUCCESS on server-01 (203.0.113.45): login after repeated failures. |
| ALT-003 | 14:32 | High | Risky removable media | server-01 | 1 removable drive event(s) on server-01. Servers should not accept unknown USB storage. |
| ALT-004 | 14:05 | High | Password reset from an unusual address | operator01 | password reset from unusual address from 198.51.100.23 on quality-tablet. |
| ALT-005 | 12:42 | High | Risky removable media | visitor on reception-laptop | opened unknown_invoice.txt from removable drive (source 10.0.0.77). |
| ALT-006 | 11:07 | High | Login burst in a short window | guest @ 10.0.0.41 | 5 failed logins for guest from 10.0.0.41 between 11:02 and 11:07, followed by a successful login at 11:08. |
| ALT-007 | 09:13 | High | Login burst in a short window | admin @ 203.0.113.45 | 4 failed logins for admin from 203.0.113.45 between 09:10 and 09:13, followed by a successful login at 09:15. |
| ALT-008 | 09:07 | Medium | Login burst in a short window | thabo @ 10.0.0.41 | 3 failed logins for thabo from 10.0.0.41 between 09:05 and 09:07, followed by a successful login at 09:09. |

Starter-log alerts are shown on the Command Centre page and are summarised in finding 3.

## 7. Screenshots

- `screenshots/command-centre.png`
- `screenshots/investigation.png`
- `screenshots/message-checker.png`
- `screenshots/incident-report.png`

## 8. Reflection

- I learned that a security alert is only the start of the work. The admin alert became useful when I put the failed logins, the successful login, and the file download in time order and could explain the chain.
- The hardest part was deciding the thresholds. Three failures is strict enough to catch a burst but noisy enough to catch typing mistakes, which is why the thabo case stayed Medium and is labelled as probably harmless.
- The message classifier reached about 86% cross-validated accuracy on only 44 messages. That is fine for practice, but it shows why a model should support a human decision instead of replacing one.
- Next time I would add a proper time range filter, export the evidence to a signed PDF, and test the rules against a second day of toy logs to see how many false positives they create.

---

Safe lab statement: this investigation used only the toy CSV files in this project. No real network, account, website, or person was scanned or tested.
