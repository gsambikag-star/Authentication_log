# Authentication Security Report

Generated on: 2026-11-25 22:35:04

## 1. Authentication Summary
- Total attempts: 15
- Successful logins: 3
- Failed logins: 12

## 2. Repeated Login Failures
- 192.168.1.10: 7 failed attempts within 60 seconds

## 3. Off-Hours Login Attempts
- 2026-11-25 02:30:12 | Username: admin | IP: 192.168.1.50 | Status: Failed
- 2026-11-25 02:30:15 | Username: admin | IP: 192.168.1.50 | Status: Failed
- 2026-11-25 02:30:18 | Username: admin | IP: 192.168.1.50 | Status: Accepted
- 2026-11-25 23:45:12 | Username: root | IP: 192.168.1.60 | Status: Failed

## 4. Rapid Login Attempts
- 192.168.1.10: 3 attempts within 10 seconds
- 192.168.1.50: 3 attempts within 10 seconds

## 5. Risk Analysis
### IP Address: 192.168.1.10
- Failed attempts: 7
- Risk score: 8
- Risk level: HIGH
- Reasons:
  - Multiple failed logins
  - Repeated login failures
  - Rapid login attempts

### IP Address: 192.168.1.20
- Failed attempts: 2
- Risk score: 0
- Risk level: LOW

### IP Address: 192.168.1.30
- Failed attempts: 0
- Risk score: 0
- Risk level: LOW

### IP Address: 192.168.1.40
- Failed attempts: 0
- Risk score: 0
- Risk level: LOW

### IP Address: 192.168.1.50
- Failed attempts: 2
- Risk score: 5
- Risk level: MEDIUM
- Reasons:
  - Off-hours login activity
  - Rapid login attempts

### IP Address: 192.168.1.60
- Failed attempts: 1
- Risk score: 2
- Risk level: LOW
- Reasons:
  - Off-hours login activity

## 6. Security Recommendations
- Investigate IP addresses classified as HIGH risk.
- Consider temporarily blocking suspicious IP addresses.
- Enable multi-factor authentication.
- Monitor repeated failed login attempts.
- Review unusual off-hours login activity.