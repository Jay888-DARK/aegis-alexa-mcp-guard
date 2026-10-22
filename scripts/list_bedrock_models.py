#!/usr/bin/env python3
"""List available AWS Bedrock models and inference profiles supporting Converse API.

Dynamically queries the AWS Bedrock control plane in the configured region.
Highlights smaller, cheaper tiers (e.g., Nova Micro/Lite, Haiku, Mini).
Does NOT hardcode any model IDs.
"""

from pathlib import Path
import os
import sys

from dotenv import load_dotenv

# Load workspace root .env
load_dotenv(Path(__file__).parent.parent / ".env")


def get_bedrock_client():
    import boto3

    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    return boto3.client("bedrock", region_name=region), region


def is_smaller_tier(identifier: str, name: str) -> bool:
    """Check if model belongs to a lighter/cheaper tier."""
    target = f"{identifier.lower()} {name.lower()}"
    keywords = ["haiku", "nova micro", "nova lite", "lite", "mini", "micro"]
    return any(k in target for k in keywords)


def main():
    try:
        client, region = get_bedrock_client()
    except Exception as e:
        print(f"Error initializing boto3 Bedrock client: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nQuerying AWS Bedrock in region: {region}\n")

    # 1. Foundation Models
    try:
        fm_resp = client.list_foundation_models()
        model_summaries = fm_resp.get("modelSummaries", [])
    except Exception as e:
        print(f"Warning: Could not fetch foundation models: {e}", file=sys.stderr)
        model_summaries = []

    # 2. Inference Profiles
    try:
        ip_resp = client.list_inference_profiles()
        profile_summaries = ip_resp.get("inferenceProfileSummaries", [])
    except Exception as e:
        print(f"Warning: Could not fetch inference profiles: {e}", file=sys.stderr)
        profile_summaries = []

    rows = []

    # Process foundation models
    for m in model_summaries:
        output_modalities = m.get("outputModalities", [])
        if "TEXT" not in output_modalities:
            continue

        model_id = m.get("modelId", "")
        provider = m.get("providerName", "")
        name = m.get("modelName", "")

        provider_lower = provider.lower()
        has_tools = "Yes" if ("anthropic" in provider_lower or "amazon" in provider_lower or "meta" in provider_lower or "cohere" in provider_lower) else "Unknown"

        smaller = is_smaller_tier(model_id, name)
        rows.append({
            "id": model_id,
            "provider": provider,
            "name": name,
            "tools": has_tools,
            "is_profile": False,
            "smaller": smaller,
        })

    # Process inference profiles
    for p in profile_summaries:
        status = p.get("status", "ACTIVE")
        if status != "ACTIVE":
            continue

        prof_id = p.get("inferenceProfileId", "")
        prof_name = p.get("inferenceProfileName", "")

        provider = "AWS Profile"
        if "anthropic" in prof_id.lower() or "claude" in prof_name.lower():
            provider = "Anthropic (Profile)"
        elif "amazon" in prof_id.lower() or "nova" in prof_name.lower():
            provider = "Amazon (Profile)"
        elif "meta" in prof_id.lower() or "llama" in prof_name.lower():
            provider = "Meta (Profile)"

        has_tools = "Yes" if ("anthropic" in prof_id.lower() or "amazon" in prof_id.lower()) else "Unknown"
        smaller = is_smaller_tier(prof_id, prof_name)

        rows.append({
            "id": prof_id,
            "provider": provider,
            "name": prof_name,
            "tools": has_tools,
            "is_profile": True,
            "smaller": smaller,
        })

    if not rows:
        print("No text/Converse models found or access restricted.")
        return

    # Print Table
    col_id_w = 48
    col_prov_w = 20
    col_name_w = 34
    col_tool_w = 10
    col_tier_w = 14

    header = (
        f"{'Model / Profile ID':<{col_id_w}} "
        f"{'Provider':<{col_prov_w}} "
        f"{'Name':<{col_name_w}} "
        f"{'Tools':<{col_tool_w}} "
        f"{'Tier':<{col_tier_w}}"
    )
    separator = "-" * (col_id_w + col_prov_w + col_name_w + col_tool_w + col_tier_w + 4)

    print("=" * len(separator))
    print("                     AWS BEDROCK TEXT & CONVERSE MODELS")
    print("=" * len(separator))
    print(header)
    print(separator)

    # Sort so smaller tiers appear prominently, then alphabetical
    rows.sort(key=lambda r: (not r["smaller"], r["provider"], r["id"]))

    for r in rows:
        tier_tag = "* LIGHT TIER" if r["smaller"] else "Standard"
        display_id = r["id"] if len(r["id"]) <= col_id_w else r["id"][:col_id_w - 3] + "..."
        display_name = r["name"] if len(r["name"]) <= col_name_w else r["name"][:col_name_w - 3] + "..."
        display_prov = r["provider"] if len(r["provider"]) <= col_prov_w else r["provider"][:col_prov_w - 3] + "..."

        line = (
            f"{display_id:<{col_id_w}} "
            f"{display_prov:<{col_prov_w}} "
            f"{display_name:<{col_name_w}} "
            f"{r['tools']:<{col_tool_w}} "
            f"{tier_tag:<{col_tier_w}}"
        )
        print(line)

    print(separator)
    print("Note: Rows flagged with '* LIGHT TIER' have smaller parameter counts, higher quotas, and lower cost.\n")


if __name__ == "__main__":
    main()
