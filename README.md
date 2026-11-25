# Authentication Log Failure & Brute-Force Monitor

## 1. Project Overview

The **Authentication Log Failure & Brute-Force Monitor** is a Python-based cybersecurity project designed to analyze authentication logs and identify suspicious login activities.

The system examines SSH authentication logs, detects repeated failed login attempts, identifies unusual login patterns, calculates risk scores for suspicious IP addresses, and automatically generates a security report.

This project demonstrates how basic log analysis and rule-based anomaly detection can help identify potential brute-force attacks and suspicious authentication behavior.

## 2. Project Objectives

- Analyze authentication log files.
- Extract important information from SSH log entries.
- Detect failed login attempts.
- Identify IP addresses with repeated login failures.
- Detect login attempts during unusual hours.
- Identify rapid login attempts within short time intervals.
- Calculate risk scores and classify suspicious IP addresses.
- Automatically generate security reports.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Regular Expressions | Extract information from log entries |
| Collections (Counter, defaultdict) | Count and group login activities |
| DateTime | Analyze login timestamps |
| pathlib | Manage report file paths |
| Git | Version control |
| GitHub | Source code hosting |
| VS Code | Development environment |

## 4. Project Structure

```text
Authentication_Log_Monitor/
│
├── logs/
│   └── sample_auth.log
│
├── reports/
│   └── security_report.md
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

## 5. Features Implemented

### Stage 1: Foundation

**Phase 1: Project Setup**
- Created the project directory and folder structure.
- Set up a Python virtual environment.
- Created the required Python modules.

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
- Counted failed attempts by IP address.
- Counted failed attempts by username.
- Counted failed attempts by IP address and username.
- Identified suspicious IP addresses using a configurable failure threshold.

### Stage 2: Anomaly Detection

**Phase 5.1: Repeated Login Failure Analysis**
- Identifies IP addresses making 3 or more failed login attempts within 60 seconds.
- Groups failed login attempts by IP address.
- Flags suspicious repeated login activity.

**Phase 5.2: Off-Hours Login Detection**
- Detects authentication attempts outside normal working hours.
- Considers 6:00 AM to 10:00 PM as normal working hours.
- Identifies both successful and failed login attempts during off-hours.

**Phase 5.3: Rapid Login Attempt Detection**
- Identifies IP addresses making 3 or more login attempts within 10 seconds.
- Considers both successful and failed login attempts.
- Helps identify potentially automated or brute-force login activity.

### Stage 3: Risk Analysis

**Phase 6: Risk Scoring and Severity Classification**
- Assigns risk points based on suspicious authentication activities.
- Calculates an overall risk score for each IP address.
- Classifies IP addresses into Low, Medium, and High risk levels.
- Displays reasons for each risk classification.

### Stage 4: Report Generation and Integration

**Phase 7: Automated Report Generation**
- Generates an automated Markdown security report.
- Includes authentication statistics.
- Displays repeated login failures.
- Lists off-hours login attempts.
- Displays rapid login activity.
- Includes risk scores and severity levels.
- Provides basic security recommendations.

**Phase 8: Main Program Integration**
- Integrated all Python modules through `main.py`.
- Executes the complete analysis using a single command.
- Automatically generates the security report after analysis.

## 6. Risk Scoring Methodology

The system assigns risk points based on the following rules:

| Suspicious Activity | Risk Points |
|---|---:|
| 3 or more failed login attempts | +2 |
| Repeated failures within 60 seconds | +3 |
| Login attempts during off-hours | +2 |
| 3 or more attempts within 10 seconds | +3 |

### Risk Classification

| Risk Score | Risk Level |
|---|---|
| 0–2 | LOW |
| 3–5 | MEDIUM |
| 6 or more | HIGH |

These thresholds are configurable educational rules used for this project.

## 7. Sample Analysis Results

The project was tested using a synthetic authentication dataset containing 15 log entries.

| Parameter | Result |
|---|---:|
| Total authentication attempts | 15 |
| Successful login attempts | 3 |
| Failed login attempts | 12 |
| IPs with repeated login failures | 1 |
| Off-hours login attempts | 4 |
| IPs with rapid login attempts | 2 |

### Risk Analysis Results

| IP Address | Risk Score | Risk Level |
|---|---:|---|
| 192.168.1.10 | 8 | HIGH |
| 192.168.1.20 | 0 | LOW |
| 192.168.1.30 | 0 | LOW |
| 192.168.1.40 | 0 | LOW |
| 192.168.1.50 | 5 | MEDIUM |
| 192.168.1.60 | 2 | LOW |

## 8. Installation and Setup

### Prerequisites

- Python 3 installed.
- Git installed.
- Visual Studio Code or another Python editor.

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### Step 2: Navigate to the Project Folder

```bash
cd Authentication_Log_Monitor
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4: Activate the Virtual Environment

For Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

## 9. Running the Project

Run the following command from the project root directory:

```bash
python main.py
```

The program automatically:

1. Reads the authentication log file.
2. Parses the log entries.
3. Detects failed login attempts.
4. Identifies suspicious authentication patterns.
5. Calculates risk scores.
6. Classifies IP addresses based on risk levels.
7. Generates the security report.

## 10. Generated Security Report

After successful execution, the report is automatically saved at:

```text
reports/security_report.md
```

The generated report contains:

- Authentication summary.
- Successful and failed login counts.
- Repeated login failure details.
- Off-hours login activities.
- Rapid login attempt details.
- Risk scores and severity classifications.
- Security recommendations.

## 11. Security Recommendations

The system provides basic recommendations based on the detected activities:

- Investigate IP addresses classified as HIGH risk.
- Consider temporarily blocking suspicious IP addresses after investigation.
- Enable Multi-Factor Authentication (MFA).
- Monitor repeated failed login attempts.
- Review unusual off-hours login activities.

## 12. Project Status

**Status: Completed**

| Stage | Description | Status |
|---|---|---|
| Stage 1 | Foundation | Completed |
| Stage 2 | Anomaly Detection | Completed |
| Stage 3 | Risk Analysis | Completed |
| Stage 4 | Report Generation and Integration | Completed |

## 13. Future Enhancements

- Support real-time authentication log monitoring.
- Add graphical dashboards for security analysis.
- Integrate email alerts for high-risk activities.
- Support multiple authentication log formats.
- Add configurable detection thresholds.
- Store historical analysis results in a database.

## 14. Disclaimer

This project uses synthetic SSH authentication logs for educational and cybersecurity learning purposes.

It demonstrates basic log analysis, rule-based anomaly detection, risk scoring, and automated reporting. It does not currently monitor live servers or automatically block suspicious IP addresses.

## Author
**Ambika G.S**