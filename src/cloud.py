import os
import boto3

def get_s3_client():
    return boto3.client(
        "s3",
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )

def download_log_from_s3(bucket: str, key: str, local_path: str) -> None:
    s3 = get_s3_client()
    print(f"[S3] Downloading s3://{bucket}/{key} -> {local_path}")
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    s3.download_file(bucket, key, local_path)

def upload_file_to_s3(bucket: str, local_path: str, key: str) -> None:
    s3 = get_s3_client()
    print(f"[S3] Uploading {local_path} -> s3://{bucket}/{key}")
    s3.upload_file(local_path, bucket, key)