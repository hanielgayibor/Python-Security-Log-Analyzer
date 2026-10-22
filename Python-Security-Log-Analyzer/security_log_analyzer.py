#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Oct 21 15:13:37 2026

@author: hanielgayibor
"""



from datetime import datetime

# -----------------------------
# 1. SETUP
# -----------------------------

failed_count = 0
success_count = 0
total_events = 0
malformed_count = 0

failed_by_ip = {}
failed_by_username = {}
failed_timestamps = {}

alerts = []

threshold = 3
username_threshold = 3
time_threshold = 10


# -----------------------------
# 2. READ AND ANALYZE THE LOG
# -----------------------------

with open("logs/auth_log.txt", "r") as log_file:

    for line_number, line in enumerate(log_file, start=1):

        if not line.strip():
            continue

        fields = line.strip().split(",")

        # Validate the number of fields
        if len(fields) != 4:
            malformed_count += 1
            print("Malformed record on line", line_number)
            continue

        timestamp_text = fields[0].strip()
        ip_address = fields[1].strip()
        username = fields[2].strip()
        event = fields[3].strip()

        # Validate required fields
        if not all(fields):
            malformed_count += 1
            print("Empty field on line", line_number)
            continue

        # Validate event type
        if event not in ["LOGIN_SUCCESS", "LOGIN_FAILED"]:
            malformed_count += 1
            print("Unknown event on line", line_number)
            continue

        # Validate timestamp
        try:
            timestamp = datetime.strptime(
                timestamp_text, "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            malformed_count += 1
            print("Malformed timestamp on line", line_number)
            continue

        total_events += 1

        # Count successful logins
        if event == "LOGIN_SUCCESS":
            success_count += 1

        # Count failed logins
        elif event == "LOGIN_FAILED":
            failed_count += 1

            # Track failures by IP address
            if ip_address not in failed_by_ip:
                failed_by_ip[ip_address] = 0

            failed_by_ip[ip_address] += 1

            # Track failures by username
            if username not in failed_by_username:
                failed_by_username[username] = 0

            failed_by_username[username] += 1

            # Store failure timestamps by IP
            if ip_address not in failed_timestamps:
                failed_timestamps[ip_address] = []

            failed_timestamps[ip_address].append(timestamp)


# -----------------------------
# 3. DISPLAY OVERALL RESULTS
# -----------------------------

print("\nSECURITY LOG ANALYZER RESULTS")
print("-----------------------------")

print("Total valid events:", total_events)
print("Successful logins:", success_count)
print("Failed logins:", failed_count)
print("Malformed records:", malformed_count)


# -----------------------------
# 4. DISPLAY FAILED LOGINS BY IP
# -----------------------------

print("\nFAILED LOGINS BY IP ADDRESS")

for ip_address, count in failed_by_ip.items():
    print(ip_address, ":", count, "failed login(s)")


# -----------------------------
# 5. DETECT SUSPICIOUS IP ADDRESSES
# -----------------------------

print("\nSUSPICIOUS IP ADDRESSES")

ip_alert_found = False

for ip_address, count in failed_by_ip.items():

    if count >= threshold:
        message = (
            f"[HIGH] IP {ip_address} had "
            f"{count} failed login attempts."
        )

        print("ALERT:", message)
        alerts.append(message)
        ip_alert_found = True

if not ip_alert_found:
    print("No IP addresses met the threshold.")


# -----------------------------
# 6. DISPLAY FAILED LOGINS BY USERNAME
# -----------------------------

print("\nFAILED LOGINS BY USERNAME")

for username, count in failed_by_username.items():
    print(username, ":", count, "failed login(s)")


# -----------------------------
# 7. DETECT REPEATED USERNAME FAILURES
# -----------------------------

print("\nUSERNAMES WITH REPEATED FAILED LOGINS")

username_alert_found = False

for username, count in failed_by_username.items():

    if count >= username_threshold:
        message = (
            f"[MEDIUM] Username '{username}' had "
            f"{count} failed login attempts."
        )

        print("ALERT:", message)
        alerts.append(message)
        username_alert_found = True

if not username_alert_found:
    print("No usernames met the threshold.")


# -----------------------------
# 8. DETECT RAPID FAILED LOGINS
# -----------------------------

print("\nTIME BETWEEN FAILED LOGIN ATTEMPTS")

rapid_attempt_found = False

for ip_address, timestamps in failed_timestamps.items():

    # Ensure timestamps are chronological
    timestamps.sort()

    for i in range(1, len(timestamps)):

        time_difference = (
            timestamps[i] - timestamps[i - 1]
        ).total_seconds()

        print(
            ip_address,
            "-",
            int(time_difference),
            "seconds between failed attempts"
        )

        if time_difference <= time_threshold:

            message = (
                f"[MEDIUM] IP {ip_address} had consecutive "
                f"failed login attempts {int(time_difference)} "
                f"seconds apart."
            )

            print("ALERT:", message)
            alerts.append(message)
            rapid_attempt_found = True

if not rapid_attempt_found:
    print("No rapid failed login attempts detected.")


# -----------------------------
# 9. DISPLAY ALL COLLECTED ALERTS
# -----------------------------

print("\nALL SECURITY ALERTS")
print("-------------------")

if alerts:
    for alert in alerts:
        print(alert)
else:
    print("No security alerts were generated.")


# -----------------------------
# 10. CREATE THE SECURITY REPORT
# -----------------------------

report = "SECURITY LOG ANALYZER REPORT\n"
report += "============================\n"

report += f"Total valid events: {total_events}\n"
report += f"Successful logins: {success_count}\n"
report += f"Failed logins: {failed_count}\n"
report += f"Malformed records: {malformed_count}\n"

report += "\nFAILED LOGINS BY IP ADDRESS\n"

for ip_address, count in failed_by_ip.items():
    report += f"{ip_address}: {count} failed login(s)\n"

report += "\nFAILED LOGINS BY USERNAME\n"

for username, count in failed_by_username.items():
    report += f"{username}: {count} failed login(s)\n"

report += "\nALL SECURITY ALERTS\n"
report += "-------------------\n"

if alerts:
    for alert in alerts:
        report += alert + "\n"
else:
    report += "No security alerts were generated.\n"


# -----------------------------
# 11. SAVE THE REPORT
# -----------------------------

with open("security_report.txt", "w") as report_file:
    report_file.write(report)

print("\nSecurity report saved to security_report.txt")
