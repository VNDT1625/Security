"""Read-only/DryRun preflight for the Prewise disposable EC2 workers."""

from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from backend.config import settings
from backend.services.cloud_sandbox_service import cloud_sandbox_service


def _client():
    return cloud_sandbox_service._client()  # noqa: SLF001 - deployment preflight


def _dry_run_params(tier: str, mode: str) -> dict[str, Any]:
    return {
        "ImageId": cloud_sandbox_service._image_id(tier, mode),  # noqa: SLF001
        "InstanceType": cloud_sandbox_service._instance_type(tier, mode),  # noqa: SLF001
        "MinCount": 1,
        "MaxCount": 1,
        "NetworkInterfaces": [
            {
                "DeviceIndex": 0,
                "SubnetId": settings.aws_sandbox_subnet_id,
                "Groups": [cloud_sandbox_service._security_group_id(mode)],  # noqa: SLF001
                "AssociatePublicIpAddress": settings.aws_sandbox_associate_public_ip,
                "DeleteOnTermination": True,
            }
        ],
        "InstanceInitiatedShutdownBehavior": "terminate",
        "MetadataOptions": {
            "HttpTokens": "required",
            "HttpEndpoint": "enabled",
            "HttpPutResponseHopLimit": 1,
            "HttpProtocolIpv6": "disabled",
            "InstanceMetadataTags": "disabled",
        },
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "ManagedBy", "Value": "PrewiseSandbox"},
                    {"Key": "PrewiseSession", "Value": "preflight-dry-run"},
                ],
            }
        ],
        "DryRun": True,
    }


def _check_mode(tier: str, mode: str) -> tuple[bool, str]:
    availability = cloud_sandbox_service.availability(tier, mode)
    if not availability["available"]:
        detail = ",".join(availability.get("missing", []))
        return False, detail or str(availability.get("reason") or "unavailable")
    try:
        client = _client()
        image_id = cloud_sandbox_service._image_id(tier, mode)  # noqa: SLF001
        images = client.describe_images(ImageIds=[image_id]).get("Images", [])
        if len(images) != 1 or images[0].get("State") != "available":
            return False, "ami_not_available"

        group_id = cloud_sandbox_service._security_group_id(mode)  # noqa: SLF001
        groups = client.describe_security_groups(GroupIds=[group_id]).get(
            "SecurityGroups", []
        )
        subnets = client.describe_subnets(
            SubnetIds=[settings.aws_sandbox_subnet_id]
        ).get("Subnets", [])
        if len(groups) != 1 or len(subnets) != 1:
            return False, "network_boundary_not_found"
        if groups[0].get("VpcId") != subnets[0].get("VpcId"):
            return False, "security_group_subnet_vpc_mismatch"

        ingress = groups[0].get("IpPermissions", [])
        if mode == "auto" and ingress:
            return False, "auto_security_group_has_ingress"
        if mode == "interactive":
            broker_group_id = os.getenv(
                "AWS_SANDBOX_BROKER_SECURITY_GROUP_ID", ""
            ).strip()
            if not broker_group_id:
                return False, "AWS_SANDBOX_BROKER_SECURITY_GROUP_ID"
            if len(ingress) != 1:
                return False, "interactive_ingress_not_exclusive"
            rule = ingress[0]
            group_pairs = rule.get("UserIdGroupPairs", [])
            if (
                rule.get("IpProtocol") != "tcp"
                or rule.get("FromPort") != 3389
                or rule.get("ToPort") != 3389
                or rule.get("IpRanges")
                or rule.get("Ipv6Ranges")
                or rule.get("PrefixListIds")
                or len(group_pairs) != 1
                or group_pairs[0].get("GroupId") != broker_group_id
            ):
                return False, "interactive_rdp_not_restricted_to_broker"

        _client().run_instances(**_dry_run_params(tier, mode))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "DryRunOperation":
            return True, "dry-run-authorized"
        return False, code
    return False, "aws-dry-run-contract-changed"


def main() -> int:
    failed = False
    for label, tier, mode in (
        ("AUTO", "pro", "auto"),
        ("INTERACTIVE", "pro", "interactive"),
    ):
        ok, detail = _check_mode(tier, mode)
        print(f"{label}={'READY' if ok else 'BLOCKED'} ({detail})")
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
