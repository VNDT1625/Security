"""Find and optionally terminate stale Prewise EC2 workers.

Dry-run is the default. Destructive execution requires both --execute and the
current AWS account id in --confirm-account.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

import boto3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="ap-southeast-1")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--older-than-minutes", type=int, default=30)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-account")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.older_than_minutes < 15:
        raise SystemExit("Refusing a cleanup window shorter than 15 minutes")
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    if args.execute and args.confirm_account != account:
        raise SystemExit("--confirm-account must exactly match the active AWS account")

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=args.older_than_minutes)
    ec2 = session.client("ec2")
    paginator = ec2.get_paginator("describe_instances")
    instance_ids: list[str] = []
    filters = [
        {"Name": "tag:ManagedBy", "Values": ["PrewiseSandbox"]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ]
    for page in paginator.paginate(Filters=filters):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                # The long-lived broker is stack-managed and never has a session tag.
                tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
                if not tags.get("PrewiseSession"):
                    continue
                if instance["LaunchTime"] <= cutoff:
                    instance_ids.append(instance["InstanceId"])

    action = "TERMINATE" if args.execute else "WOULD_TERMINATE"
    for instance_id in sorted(instance_ids):
        print(f"{action} {instance_id}")
    if args.execute and instance_ids:
        ec2.terminate_instances(InstanceIds=instance_ids)
    print(f"ACCOUNT={account} STALE_WORKERS={len(instance_ids)} EXECUTE={args.execute}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
