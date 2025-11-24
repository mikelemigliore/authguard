# AuthGuard – AI-Powered Security Incident Detection System

## Overview

AuthGuard is a cybersecurity-focused project designed to simulate a lightweight SIEM system capable of ingesting authentication logs, detecting suspicious activity, and generating SOC-grade incident reports using AI. It integrates with AWS services for cloud storage and automates the full detection/reporting workflow end-to-end.

This project helped me gain real experience in:

- Threat detection logic
- Log analysis
- Cloud automation (AWS S3 + IAM)
- AI-powered automation
- Python scripting and modular architecture

---

## Features

### Log Ingestion

- Reads logs from a local file
- Automatically downloads logs from AWS S3 when enabled

### Threat Detection

Detects two major authentication attack patterns:

- **Brute-force attacks**
- **Password spraying**

Rules are completely configurable via `rules.json`.

### AI-Generated Incident Reports

Every alert triggers an AI-written report including:

- Summary of the event
- Attack type
- Severity level
- Attacker behavior
- Impact assessment
- Recommended remediation
- SOC team follow-up steps

### AWS Cloud Integration

- Downloads logs from S3
- Uploads generated incident reports back to S3
- Uses IAM credentials and secure environment variables

### Config-Driven Architecture

Customize:

- S3 usage
- Bucket names
- Log locations
- Detection rules

All through JSON configuration files.

## Example Outputs
<img height="287" alt="Screenshot 2025-11-23 130107" src="https://github.com/user-attachments/assets/ea68839f-fc22-4a3f-8f9e-4b18a1bc9b01" />

<img height="190" alt="Screenshot 2025-11-23 130132" src="https://github.com/user-attachments/assets/a11305a6-0eb2-41d1-b129-858db2e61162" />

<img height="767" alt="Screenshot 2025-11-23 130211" src="https://github.com/user-attachments/assets/969d7836-8410-4226-847c-b87af9869e0a" />

<img height="338" alt="Screenshot 2025-11-23 130447" src="https://github.com/user-attachments/assets/6d3890d1-0a6c-43b7-9c84-0b20ac57f31c" />

<img height="487" alt="Screenshot 2025-11-23 130458" src="https://github.com/user-attachments/assets/da320a62-b9a1-4591-bc48-313dd7654fd6" />


