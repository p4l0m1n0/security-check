# security-check
Linux Debian-based security audit script that checks for updates, network and services connections, malware detection, and log review.
=======
# Security Check Script

A Linux security auditing tool that checks for system updates, listening ports, running services, rootkit indicators, malware, and authentication logs in one automated workflow.

This project began as a Bash-based server hardening and malware detection script and was later rewritten in Python to improve structure, readability, and maintainability.

## Features

- Checks for available system updates.
- Lists listening TCP and UDP ports with process information.
- Detects running Docker containers if Docker is installed.
- Runs `rkhunter` for rootkit detection.
- Runs ClamAV for malware scanning.
- Reviews recent login activity.
- Reviews failed login attempts.
- Displays recent system warnings.
- Searches authentication logs for failed password attempts.
- Displays recent sudo activity.
- Shows fail2ban jail status when fail2ban is installed.

## Requirements

- Python 3
- Linux-based system
- `sudo` privileges for full functionality

### Optional tools

- `rkhunter`
- `clamav`
- `clamav-freshclam`
- `fail2ban`
- `docker`

## Usage

Run the script with:

```bash
sudo python3 security-check.py
```

## How It Works

The script is organized into sections:

1. System update checks.
2. Network and service enumeration.
3. Rootkit and malware detection.
4. Authentication and log analysis.

It is designed to be non-destructive and to provide clear output that can be reviewed manually by the administrator.

## Project Background

The original Bash version of this project focused on layered host security checks, including package updates, service enumeration, rootkit detection, malware scanning, and log analysis. The Python version expands on that structure while keeping the same security-focused workflow.

## Files

- `security-check.py` — main Python script.
- `README.md` — project documentation.
- `docs/` — optional folder for related documentation, screenshots, and the original Bash-based writeup.

## Notes

- Some checks may be skipped if the required tools are not installed, although you will be warned if they are not.
- The script should be run with `sudo` for full access to logs and system information.
- Scanning the full filesystem with ClamAV may take a while depending on system size.
