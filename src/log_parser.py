
import re
from datetime import datetime


# Regular expression to identify authentication log details
LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3}) "
    r"(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"server sshd\[\d+\]: "
    r"(?P<status>Failed|Accepted) password for "
    r"(?P<username>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<port>\d+) ssh2$"
)


def parse_log(line):
    match = LOG_PATTERN.search(line.strip())

    if not match:
        return None

    data = match.groupdict()

    # Convert extracted date and time into datetime object
    timestamp = datetime.strptime(
        f"2026 {data['month']} {data['day']} {data['time']}",
        "%Y %b %d %H:%M:%S"
    )

    return {
        "timestamp": timestamp,
        "username": data["username"],
        "ip": data["ip"],
        "status": data["status"],
        "port": int(data["port"])
    }


def read_logs(file_path):
    parsed_logs = []

    with open(file_path, "r") as file:
        for line in file:
            result = parse_log(line)

            if result:
                parsed_logs.append(result)
            elif line.strip():
                print("Invalid log entry:", line.strip())

    return parsed_logs


# Test the parser independently
if __name__ == "__main__":

    logs = read_logs("logs/sample_auth.log")

    print("\nAUTHENTICATION LOG ANALYSIS")
    print("-" * 40)

    for log in logs:
        print(log)

    print("\nTotal valid log entries:", len(logs))
