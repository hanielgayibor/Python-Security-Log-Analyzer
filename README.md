# Python Security Log Analyzer

## Overview
The Python Security Log Analyzer is a beginner cybersecurity project built to practice Python programming and basic security log analysis. It reads fictional authentication logs, counts successful and failed login attempts, and identifies activity that may require further investigation.

## Project Objectives
- Read and process authentication log files.
- Count successful and failed login events.
- Track failed login attempts by IP address and username.
- Detect repeated failed logins using configurable thresholds.
- Identify rapid failed login attempts.
- Validate log entries and handle malformed records.
- Generate a security report containing event counts and alerts.

## Tools and Technologies
- **Language:** Python
- **IDE:** Spyder
- **Python concepts:** File handling, loops, conditional statements, dictionaries, lists, functions, and exception handling
- **Security concepts:** Authentication logs, suspicious login activity, threshold-based detection, and security reporting

## How It Works
1. Reads authentication records from `logs/auth_log.txt`.
2. Validates the records and processes valid events.
3. Counts successful and failed login attempts.
4. Tracks failures by IP address and username.
5. Flags repeated failures and rapid attempts based on configured rules.
6. Writes the results and security alerts to `security_report.txt`.

## Sample Results
Using the original sample log file, the analyzer processed:

- **Total events:** 12
- **Successful logins:** 5
- **Failed logins:** 7
- **IP flagged for repeated failures:** `192.168.1.50`

## Testing
The project was tested with normal log entries, invalid event types, missing fields, invalid timestamps, repeated failed logins, username thresholds, report generation, and an empty log file.

See [PHASE_9_TESTING.md](PHASE_9_TESTING.md) for the testing summary.

## What I Learned
- How to process text files using Python.
- How to use dictionaries to count events by IP address and username.
- How to validate input and handle invalid records.
- How to use thresholds to flag potentially suspicious activity.
- How to test a program and document its results.
