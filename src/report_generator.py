
from collections import Counter
from datetime import datetime
from pathlib import Path


def generate_report(logs, risk_results, repeated_ips,
                    off_hours_logs, rapid_ips):

    total_attempts = len(logs)

    successful = sum(
        1 for log in logs if log["status"] == "Accepted"
    )

    failed = sum(
        1 for log in logs if log["status"] == "Failed"
    )

    failed_counts = Counter(
        log["ip"] for log in logs
        if log["status"] == "Failed"
    )

    report = []

    report.append("# Authentication Security Report")
    report.append("")
    report.append(
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    report.append("")
    report.append("## 1. Authentication Summary")
    report.append(f"- Total attempts: {total_attempts}")
    report.append(f"- Successful logins: {successful}")
    report.append(f"- Failed logins: {failed}")
    report.append("")
    report.append("## 2. Repeated Login Failures")

    if repeated_ips:
        for ip, count in repeated_ips.items():
            report.append(
                f"- {ip}: {count} failed attempts within 60 seconds"
            )
    else:
        report.append("- No repeated failures detected.")

    report.append("")
    report.append("## 3. Off-Hours Login Attempts")

    if off_hours_logs:
        for log in off_hours_logs:
            report.append(
                f"- {log['timestamp']} | "
                f"Username: {log['username']} | "
                f"IP: {log['ip']} | "
                f"Status: {log['status']}"
            )
    else:
        report.append("- No off-hours attempts detected.")

    report.append("")
    report.append("## 4. Rapid Login Attempts")

    if rapid_ips:
        for ip, count in rapid_ips.items():
            report.append(
                f"- {ip}: {count} attempts within 10 seconds"
            )
    else:
        report.append("- No rapid attempts detected.")

    report.append("")
    report.append("## 5. Risk Analysis")

    for ip, details in sorted(risk_results.items()):
        report.append(f"### IP Address: {ip}")
        report.append(f"- Failed attempts: {failed_counts[ip]}")
        report.append(f"- Risk score: {details['score']}")
        report.append(f"- Risk level: {details['level']}")

        if details["reasons"]:
            report.append("- Reasons:")
            for reason in details["reasons"]:
                report.append(f"  - {reason}")

        report.append("")

    report.append("## 6. Security Recommendations")
    report.append("- Investigate IP addresses classified as HIGH risk.")
    report.append("- Consider temporarily blocking suspicious IP addresses.")
    report.append("- Enable multi-factor authentication.")
    report.append("- Monitor repeated failed login attempts.")
    report.append("- Review unusual off-hours login activity.")

    # Create reports folder if it does not exist
    report_folder = Path("reports")
    report_folder.mkdir(exist_ok=True)

    # Save report
    report_path = report_folder / "security_report.md"

    with open(report_path, "w", encoding="utf-8") as file:
        file.write("\n".join(report))

    return report_path


if __name__ == "__main__":

    from log_parser import read_logs
    from anomaly_detector import (
        detect_repeated_failures,
        detect_off_hours_logins,
        detect_rapid_attempts
    )
    from risk_analyzer import calculate_risk_scores

    logs = read_logs("logs/sample_auth.log")

    repeated_ips = detect_repeated_failures(logs)
    off_hours_logs = detect_off_hours_logins(logs)
    rapid_ips = detect_rapid_attempts(logs)
    risk_results = calculate_risk_scores(logs)

    report_path = generate_report(
        logs,
        risk_results,
        repeated_ips,
        off_hours_logs,
        rapid_ips
    )

    print("\nSECURITY REPORT GENERATED")
    print("-" * 40)
    print("Report saved at:", report_path)
