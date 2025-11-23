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

