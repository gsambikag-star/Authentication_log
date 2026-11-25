
from src.log_parser import read_logs
from src.failure_detector import detect_failures, check_threshold

from src.anomaly_detector import (
    detect_repeated_failures,
    detect_off_hours_logins,
    detect_rapid_attempts
)

from src.risk_analyzer import calculate_risk_scores
from src.report_generator import generate_report


def main():

    print("\nAUTHENTICATION LOG MONITOR")
    print("=" * 50)

    # Step 1: Read authentication logs
    logs = read_logs("logs/sample_auth.log")

    print("\nTotal log entries:", len(logs))

    # Step 2: Detect failed login attempts
    failed_logs, ip_counts, username_counts, ip_username_counts = (
        detect_failures(logs)
    )

    print("Total failed login attempts:", len(failed_logs))

    suspicious_ips = check_threshold(ip_counts)

    print("\nSuspicious IP addresses:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(ip, ":", count, "failed attempts")
    else:
        print("No suspicious IP addresses found.")

    # Step 3: Detect anomalies
    repeated_ips = detect_repeated_failures(logs)
    off_hours_logs = detect_off_hours_logins(logs)
    rapid_ips = detect_rapid_attempts(logs)

    print("\nAnomaly Detection Summary")
    print("-" * 40)
    print("Repeated failure IPs:", len(repeated_ips))
    print("Off-hours login attempts:", len(off_hours_logs))
    print("Rapid login IPs:", len(rapid_ips))

    # Step 4: Calculate risk scores
    risk_results = calculate_risk_scores(logs)

    print("\nRisk Analysis")
    print("-" * 40)

    for ip, details in sorted(risk_results.items()):
        print(
            ip,
            "| Score:", details["score"],
            "| Risk:", details["level"]
        )

    # Step 5: Generate security report
    report_path = generate_report(
        logs,
        risk_results,
        repeated_ips,
        off_hours_logs,
        rapid_ips
    )

    print("\n" + "=" * 50)
    print("PROJECT EXECUTION COMPLETED")
    print("Security report generated at:", report_path)
    print("=" * 50)


if __name__ == "__main__":
    main()
