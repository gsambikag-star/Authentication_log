
from collections import Counter


def detect_failures(logs):

    # Store failed login entries
    failed_logs = []

    for log in logs:
        if log["status"] == "Failed":
            failed_logs.append(log)

    # Count failures by IP address
    ip_counts = Counter(
        log["ip"] for log in failed_logs
    )

    # Count failures by username
    username_counts = Counter(
        log["username"] for log in failed_logs
    )

    # Count failures by IP and username combination
    ip_username_counts = Counter(
        (log["ip"], log["username"])
        for log in failed_logs
    )

    return failed_logs, ip_counts, username_counts, ip_username_counts


def check_threshold(ip_counts, threshold=5):

    suspicious_ips = {}

    for ip, count in ip_counts.items():

        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips


# Test the failure detector independently
if __name__ == "__main__":

    from log_parser import read_logs

    logs = read_logs("logs/sample_auth.log")

    failed_logs, ip_counts, username_counts, ip_username_counts = detect_failures(logs)

    suspicious_ips = check_threshold(ip_counts)

    print("\nFAILED LOGIN DETECTION")
    print("-" * 40)

    print("\nTotal failed attempts:", len(failed_logs))

    print("\nFailed attempts by IP address:")
    for ip, count in ip_counts.items():
        print(ip, ":", count)

    print("\nFailed attempts by username:")
    for username, count in username_counts.items():
        print(username, ":", count)

    print("\nFailed attempts by IP and username:")
    for (ip, username), count in ip_username_counts.items():
        print(ip, "-", username, ":", count)

    print("\nIP addresses exceeding threshold:")
    for ip, count in suspicious_ips.items():
        print(ip, ":", count, "failed attempts")
