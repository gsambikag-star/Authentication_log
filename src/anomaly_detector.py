
from collections import defaultdict

def detect_repeated_failures(logs, threshold=3):
    ip_failures = defaultdict(list)

    for log in logs:
        if log["status"] == "Failed":
            ip_failures[log["ip"]].append(log["timestamp"])

    suspicious_ips = {}

    for ip, timestamps in ip_failures.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window = [
                timestamp for timestamp in timestamps
                if 0 <= (timestamp - timestamps[i]).total_seconds() <= 60
            ]

            if len(window) >= threshold:
                suspicious_ips[ip] = len(window)
                break

    return suspicious_ips


def detect_off_hours_logins(logs):
    suspicious_logins = []

    for log in logs:
        login_hour = log["timestamp"].hour

        if login_hour >= 22 or login_hour < 6:
            suspicious_logins.append(log)

    return suspicious_logins


def detect_rapid_attempts(logs, threshold=3, time_window=10):
    ip_attempts = {}

    for log in logs:
        ip = log["ip"]

        if ip not in ip_attempts:
            ip_attempts[ip] = []

        ip_attempts[ip].append(log["timestamp"])

    suspicious_ips = {}

    for ip, timestamps in ip_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 0

            for timestamp in timestamps:
                difference = (timestamp - timestamps[i]).total_seconds()

                if 0 <= difference <= time_window:
                    count += 1

            if count >= threshold:
                suspicious_ips[ip] = count
                break

    return suspicious_ips


if __name__ == "__main__":
    from log_parser import read_logs

    logs = read_logs("logs/sample_auth.log")

    suspicious_ips = detect_repeated_failures(logs)

    print("\nREPEATED LOGIN FAILURE ANALYSIS")
    print("-" * 40)

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(ip, ":", count, "failed attempts within 60 seconds")
    else:
        print("No suspicious repeated failures detected.")


    off_hours = detect_off_hours_logins(logs)

    print("\nOFF-HOURS LOGIN DETECTION")
    print("-" * 40)

    if off_hours:
        for log in off_hours:
            print(
                log["timestamp"],
                "| Username:", log["username"],
                "| IP:", log["ip"],
                "| Status:", log["status"]
            )
    else:
        print("No off-hours login attempts detected.")


    rapid_attempts = detect_rapid_attempts(logs)

    print("\nRAPID LOGIN ATTEMPT DETECTION")
    print("-" * 40)

    if rapid_attempts:
        for ip, count in rapid_attempts.items():
            print(ip, ":", count, "login attempts within 10 seconds")
    else:
        print("No rapid login attempts detected.")
