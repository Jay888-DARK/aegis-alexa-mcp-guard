#!/usr/bin/env python3
"""Single-roundtrip diagnostic tool to verify AWS Bedrock Converse API connectivity.

Reads BEDROCK_MODEL_ID and AWS_REGION from .env, sends a minimal prompt,
measures latency, reports token usage, and diagnoses common error codes.
"""

from pathlib import Path
import os
import sys
import time

from dotenv import load_dotenv

# Load workspace root .env
load_dotenv(Path(__file__).parent.parent / ".env")


ERROR_EXPLANATIONS = {
    "AccessDeniedException": (
        "Your AWS credentials lack 'bedrock:InvokeModel' permissions, or the model access agreement is not granted in the AWS Bedrock console."
    ),
    "ThrottlingException": (
        "Your AWS account has exceeded the request rate limit (RPS) or daily input/output token quota for this model in this region."
    ),
    "ValidationException": (
        "The model identifier is invalid for this region, or the specified model does not support the Converse API / toolConfig format."
    ),
    "ResourceNotFoundException": (
        "The requested model version does not exist in this region or has reached its official End-of-Life (EOL)."
    ),
}


def main():
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError

    model_id = os.getenv("BEDROCK_MODEL_ID")
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"

    print("=" * 64)
    print("               AWS BEDROCK CONVERSE PING TOOL")
    print("=" * 64)
    print(f"Target Model ID: {model_id or '(NOT SET)'}")
    print(f"Target Region:  {region}")

    if not model_id:
        print("\n[ERROR] BEDROCK_MODEL_ID environment variable is not set.", file=sys.stderr)
        print("Please set BEDROCK_MODEL_ID in your .env file or environment.", file=sys.stderr)
        sys.exit(1)

    try:
        client = boto3.client("bedrock-runtime", region_name=region)
    except Exception as e:
        print(f"\n[ERROR] Failed to initialize Bedrock client: {e}", file=sys.stderr)
        sys.exit(1)

    print("\nSending probe request: 'Reply with the word OK' (maxTokens=20, temp=0)...")
    start_time = time.perf_counter()

    try:
        response = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": "Reply with the word OK"}]}],
            inferenceConfig={"maxTokens": 20, "temperature": 0.0},
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        usage = response.get("usage", {})
        in_tokens = usage.get("inputTokens", "N/A")
        out_tokens = usage.get("outputTokens", "N/A")
        total_tokens = usage.get("totalTokens", "N/A")

        reply_content = response.get("output", {}).get("message", {}).get("content", [])
        reply_text = "".join(b.get("text", "") for b in reply_content if "text" in b).strip()

        print("\n" + "=" * 64)
        print("                       PING SUCCESSFUL")
        print("=" * 64)
        print(f"Status:        HTTP 200 OK")
        print(f"Model ID:      {model_id}")
        print(f"Region:        {region}")
        print(f"Latency:       {elapsed_ms:.1f} ms")
        print(f"Tokens:        Input: {in_tokens} | Output: {out_tokens} | Total: {total_tokens}")
        print(f"Model Reply:   \"{reply_text}\"")
        print("=" * 64 + "\n")
        sys.exit(0)

    except ClientError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        error_code = e.response.get("Error", {}).get("Code", "ClientError")
        error_message = e.response.get("Error", {}).get("Message", str(e))

        print("\n" + "=" * 64)
        print("                         PING FAILED")
        print("=" * 64)
        print(f"Error Code:    {error_code}")
        print(f"Latency:       {elapsed_ms:.1f} ms")
        print(f"Message:       {error_message}")
        print("-" * 64)

        explanation = ERROR_EXPLANATIONS.get(
            error_code,
            f"An AWS client error occurred ({error_code}). Check AWS credentials and service permissions."
        )
        print(f"Diagnosis:     {explanation}")
        print("=" * 64 + "\n")
        sys.exit(1)

    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        print("\n" + "=" * 64)
        print("                         PING FAILED")
        print("=" * 64)
        print(f"Error Type:    {type(e).__name__}")
        print(f"Latency:       {elapsed_ms:.1f} ms")
        print(f"Message:       {e}")
        print("=" * 64 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
