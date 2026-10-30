# Brute-Force Detection Lab with Splunk

## Objective
Build a home SIEM lab on my own computer and detect repeated failed Windows logins.

## Environment
- OS: Windows 11 (AMD Ryzen 7, 24 GB RAM)
- SIEM: Splunk Enterprise 10.6.1.1, installed locally
- Log source: Windows Security event log (local event log input)

## What I did
1. Installed Splunk Enterprise and logged in at localhost:8000.
2. Added the Windows Security and System event logs as a data input.
3. Confirmed data was arriving (77,495 events in the index).
4. Generated failed logins on my own machine with a Command Prompt loop using fake user names.
5. Searched for failed logons (Event ID 4625) and counted them by source address.
6. Saved a scheduled alert for repeated failures.

## Detection queries
Failed logons:
`index=main source="WinEventLog:Security" EventCode=4625`

Count by source, more than 5 failures:
`index=main source="WinEventLog:Security" EventCode=4625 | stats count by Source_Network_Address | where count > 5`

## Findings
- Splunk showed 11 failed logons (4625) from source address 127.0.0.1 within 15 minutes, with 12 different account names.
- Many failures from one source in a short time is the typical pattern of a brute-force or password-guessing attempt.
- MITRE ATT&CK: T1110 Brute Force (Credential Access)

## Alert
- Name: Possible Brute Force - Multiple Failed Logins
- Schedule: every 5 minutes (cron `*/5 * * * *`), time range last 15 minutes
- Trigger: number of results greater than 0
- Action: add to Triggered Alerts
- Result: the alert triggered successfully (2026-10-29 17:15).

## What I learned
- Event ID 4625 is a failed logon and 4624 is a successful logon.
- Windows may log only one event if the same user name repeats, so I used different fake user names.
- How to turn a search into a scheduled alert in Splunk.

## Next steps
- Add a search for a successful login (4624) after many failures.
- Build a dashboard and test the same detection with Linux logs.
