import json
import os
from dotenv import load_dotenv

load_dotenv()

from src.parser import load_logs
from src.detector import run_detection
from src.ai_assistant import generate_incident_report, save_incident_report
from src.cloud import download_log_from_s3, upload_file_to_s3


def main():
    
    with open("config/settings.json", "r", encoding="utf-8") as f:
        settings = json.load(f)

    use_s3 = settings.get("use_s3", False)
    log_bucket = settings.get("log_bucket")
    log_key = settings.get("log_key")
    output_bucket = settings.get("output_bucket")

    # Local paths
    log_file = "logs/sample.log"
    rules_file = "config/rules.json"

    # Download logs from S3 
    if use_s3 and log_bucket and log_key:
        download_log_from_s3(log_bucket, log_key, log_file)

    # Parse logs + detect attacks 
    entries = load_logs(log_file)
    alerts = run_detection(entries, rules_file)

    print("=== DETECTION ALERTS ===")
    for alert in alerts:
        print(alert)

    # Generate AI incident reports
    print("\n=== GENERATING AI INCIDENT REPORTS ===")
    for idx, alert in enumerate(alerts, start=1):
        report = generate_incident_report(alert)
        local_report_path = save_incident_report(report)

        # Upload reports to S3 
        if use_s3 and output_bucket:
            s3_key = f"incident_reports/{os.path.basename(local_report_path)}"
            upload_file_to_s3(output_bucket, local_report_path, s3_key)


if __name__ == "__main__":
    main()
