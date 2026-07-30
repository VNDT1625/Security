from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IAM_POLICY = ROOT / "infra" / "aws-sandbox" / "iam-policy.json"
PREFLIGHT = ROOT / "infra" / "aws-sandbox" / "preflight.py"


def _statement(policy: dict, sid: str) -> dict:
    for statement in policy["Statement"]:
        if statement.get("Sid") == sid:
            return statement
    raise AssertionError(f"missing IAM statement {sid}")


def test_aws_sandbox_iam_policy_is_tag_scoped_and_least_privilege() -> None:
    policy = json.loads(IAM_POLICY.read_text(encoding="utf-8"))
    actions = {
        action
        for statement in policy["Statement"]
        for action in (
            statement["Action"]
            if isinstance(statement["Action"], list)
            else [statement["Action"]]
        )
    }

    assert "ec2:RunInstances" in actions
    assert "ec2:TerminateInstances" in actions
    assert "ec2:CreateTags" in actions
    assert "ec2:StopInstances" not in actions
    assert "ec2:DeleteTags" not in actions
    assert "*" not in actions

    infrastructure = _statement(policy, "LaunchUsingSandboxInfrastructure")
    assert "arn:aws:ec2:*:*:instance/*" not in infrastructure["Resource"]

    run = _statement(policy, "LaunchOnlyTaggedSandboxInstances")
    assert run["Condition"]["StringEquals"]["aws:RequestTag/ManagedBy"] == (
        "PrewiseSandbox"
    )
    assert run["Resource"] == "arn:aws:ec2:*:*:instance/*"

    tag = _statement(policy, "TagSandboxWorkersAtLaunch")
    assert tag["Condition"]["StringEquals"]["ec2:CreateAction"] == "RunInstances"
    assert tag["Condition"]["StringEquals"]["aws:RequestTag/ManagedBy"] == (
        "PrewiseSandbox"
    )

    terminate = _statement(policy, "StopOnlyPrewiseSandboxWorkers")
    assert terminate["Resource"] == "arn:aws:ec2:*:*:instance/*"
    assert terminate["Condition"]["StringEquals"]["ec2:ResourceTag/ManagedBy"] == (
        "PrewiseSandbox"
    )


def test_aws_sandbox_preflight_is_dry_run_and_uses_cleanup_tags() -> None:
    source = PREFLIGHT.read_text(encoding="utf-8")

    assert '"DryRun": True' in source
    assert '{"Key": "ManagedBy", "Value": "PrewiseSandbox"}' in source
    assert '{"Key": "PrewiseSession", "Value": "preflight-dry-run"}' in source
    assert "_client().run_instances(**_dry_run_params(tier, mode))" in source
    assert "terminate_instances" not in source
