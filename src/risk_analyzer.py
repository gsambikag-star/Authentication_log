

from collections import Counter

from src.log_parser import read_logs
from src.anomaly_detector import (
    detect_repeated_failures,
    detect_off_hours_logins,
    detect_rapid_attempts
)



def calculate_risk_scores(logs):

    # Count failed attempts for each IP
    failed_logs = [
        log for log in logs
        if log["status"] == "Failed"
    ]

    failed_counts = Counter(
        log["ip"] for log in failed_logs
    )

    # Detect suspicious activities
    repeated_ips = detect_repeated_failures(logs)

    off_hours_logs = detect_off_hours_logins(logs)

    off_hours_counts = Counter(
        log["ip"] for log in off_hours_logs
    )

    rapid_ips = detect_rapid_attempts(logs)

    # Get all IP addresses
    all_ips = set(log["ip"] for log in logs)

    risk_results = {}

    for ip in all_ips:

        score = 0
        reasons = []

        # Rule 1: Multiple failed attempts
        if failed_counts[ip] >= 3:
            score += 2
            reasons.append("Multiple failed logins")

        # Rule 2: Repeated failures
        if ip in repeated_ips:
            score += 3
            reasons.append("Repeated login failures")

        # Rule 3: Off-hours activity
        if off_hours_counts[ip] > 0:
            score += 2
            reasons.append("Off-hours login activity")

        # Rule 4: Rapid login attempts
        if ip in rapid_ips:
            score += 3
            reasons.append("Rapid login attempts")

        # Assign risk level
        if score >= 6:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        risk_results[ip] = {
            "score": score,
            "level": level,
            "reasons": reasons
        }

    return risk_results


if __name__ == "__main__":

    logs = read_logs("logs/sample_auth.log")

    results = calculate_risk_scores(logs)

    print("\nAUTHENTICATION RISK ANALYSIS")
    print("=" * 50)

    for ip, details in sorted(results.items()):

        print("\nIP Address:", ip)
        print("Risk Score:", details["score"])
        print("Risk Level:", details["level"])

        if details["reasons"]:
            print("Reasons:")
            for reason in details["reasons"]:
                print("-", reason)
        else:
            print("Reasons: No major suspicious activity")

        print("-" * 50)
