# Authentication Log Failure & Brute-Force Monitor

## Project Overview

The Authentication Log Failure & Brute-Force Monitor is a Python-based cybersecurity project that analyzes authentication logs to identify repeated failed login attempts and potentially suspicious IP addresses.

The project uses synthetic SSH authentication logs to demonstrate how suspicious login activity can be detected.

## Objectives

- Read and analyze authentication log files.
- Extract important details such as timestamp, username, IP address, login status, and port number.
- Identify failed login attempts.
- Count failed attempts by IP address and username.
- Detect IP addresses with repeated failed login attempts using a configurable threshold.

## Technologies Used

- Python
- Regular Expressions
- Collections (Counter)
- Git and GitHub
- VS Code

## Project Structure

```text
Authentication_Log_Monitor/
│
├── logs/
│   └── sample_auth.log
│
├── reports/
│
├── src/
│   ├── __init__.py
│   ├── log_parser.py
│   ├── failure_detector.py
│   ├── anomaly_detector.py
│   ├── risk_analyzer.py
│   └── report_generator.py
│
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Features Completed

### Stage 1: Foundation – Completed

**Phase 1: Project Setup**
- Created the project directory and folder structure.
- Set up a Python virtual environment.
- Created the required Python files.

**Phase 2: Authentication Log Dataset**
- Created a synthetic SSH authentication log file.
- Included successful and failed login attempts.
- Included different usernames and IP addresses.

**Phase 3: Log Parsing**
- Used regular expressions to extract information from log entries.
- Extracted timestamps, usernames, IP addresses, login statuses, and port numbers.
- Identified invalid log entries.

**Phase 4: Failed Login Detection**
- Identified failed login attempts.
- Counted failed attempts by IP address and username.
- Identified suspicious IP addresses using a configurable failure threshold.

### Stage 2: Anomaly Detection – Completed

**Phase 5.1: Repeated Login Failure Analysis**
- Identifies IP addresses making 3 or more failed login attempts within 60 seconds.
- Groups failed attempts by IP address.
- Flags suspicious repeated login activity.

**Phase 5.2: Off-Hours Login Detection**
- Detects authentication attempts outside normal working hours.
- Considers 6:00 AM to 10:00 PM as normal working hours.
- Identifies both successful and failed login attempts during off-hours.

**Phase 5.3: Rapid Login Attempt Detection**
- Identifies IP addresses making 3 or more login attempts within 10 seconds.
- Considers both successful and failed authentication attempts.
- Helps identify potentially automated or brute-force login activity.

## Project Status

- Stage 1 – Foundation: Completed
- Stage 2 – Anomaly Detection: Completed
- Stage 3 – Risk Analysis: Upcoming
- Stage 4 – Automated Report Generation: Upcoming

The project currently supports authentication log parsing, failed login detection, and anomaly detection using synthetic SSH authentication logs.


## How to Run the Project

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the project directory

```bash
cd Authentication_Log_Monitor
```

### 3. Create and activate a virtual environment

For Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 4. Run the log parser

```bash
python src/log_parser.py
```

### 5. Run failed login detection

```bash
python src/failure_detector.py
```

## Detection Threshold

The current failed-login detection threshold is **5 attempts**.

An IP address is flagged as suspicious when it has 5 or more failed login attempts in the analyzed log file.


## Disclaimer

This project uses synthetic authentication logs for educational and cybersecurity learning purposes. It does not monitor real systems or perform live intrusion detection.

## Author 
**Ambika G.S**