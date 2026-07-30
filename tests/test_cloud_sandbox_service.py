from __future__ import annotations

import re
from typing import Any

import pytest

from backend.config import settings
from backend.services.cloud_sandbox_service import (
    CloudSandboxProvisioningError,
    CloudSandboxService,
)


class FakeWaiter:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def wait(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)
        if self.error:
            raise self.error


class FakeEC2:
    def __init__(
        self,
        *,
        waiter_error: Exception | None = None,
        termination_waiter_error: Exception | None = None,
        describe_response: dict[str, Any] | None = None,
    ) -> None:
        self.waiters = {
            "instance_running": FakeWaiter(waiter_error),
            "instance_status_ok": FakeWaiter(),
            "instance_terminated": FakeWaiter(termination_waiter_error),
        }
        self.run_params: dict[str, Any] | None = None
        self.terminated: list[str] = []
        self.describe_response = describe_response
        self.describe_calls: list[dict[str, Any]] = []

    def run_instances(self, **params: Any) -> dict[str, Any]:
        self.run_params = params
        return {"Instances": [{"InstanceId": "i-test123"}]}

    def get_waiter(self, name: str) -> FakeWaiter:
        return self.waiters[name]

    def describe_instances(self, **kwargs: Any) -> dict[str, Any]:
        self.describe_calls.append(kwargs)
        return self.describe_response or {
            "Reservations": [
                {"Instances": [{"PublicDnsName": "sandbox.example.test"}]}
            ]
        }

    def terminate_instances(self, *, InstanceIds: list[str]) -> None:  # noqa: N803
        self.terminated.extend(InstanceIds)


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "aws_sandbox_ami_id", "ami-pro")
    monkeypatch.setattr(settings, "aws_sandbox_max_ami_id", "ami-max")
    monkeypatch.setattr(settings, "aws_sandbox_subnet_id", "subnet-test")
    monkeypatch.setattr(settings, "aws_sandbox_security_group_id", "sg-test")
    monkeypatch.setattr(settings, "aws_sandbox_associate_public_ip", False)
    monkeypatch.setattr(settings, "sandbox_public_base_url", "https://api.example.test")


def test_max_vm_bootstrap_has_agent_and_mandatory_self_termination(monkeypatch) -> None:
    _configure(monkeypatch)
    fake = FakeEC2()
    service = CloudSandboxService()
    monkeypatch.setattr(service, "_client", lambda: fake)

    instance_id, remote_url = service.provision(
        "session-123",
        "user-123",
        "2026-07-18T18:30:00+00:00",
        "max",
        "agent-secret",
    )

    assert instance_id == "i-test123"
    assert remote_url == ""
    assert fake.run_params is not None
    assert fake.run_params["ImageId"] == "ami-max"
    assert fake.run_params["InstanceType"] == settings.aws_sandbox_max_instance_type
    assert fake.run_params["InstanceInitiatedShutdownBehavior"] == "terminate"
    assert fake.run_params["ClientToken"] == "prewise-session-123"
    tags = fake.run_params["TagSpecifications"][0]["Tags"]
    assert {"Key": "ManagedBy", "Value": "PrewiseSandbox"} in tags
    assert {"Key": "PrewiseSession", "Value": "session-123"} in tags
    assert {"Key": "SandboxMode", "Value": "auto"} in tags
    network = fake.run_params["NetworkInterfaces"][0]
    assert network["AssociatePublicIpAddress"] is False
    assert network["Groups"] == ["sg-test"]
    assert fake.waiters["instance_status_ok"].calls
    user_data = fake.run_params["UserData"]
    assert "shutdown.exe" in user_data
    assert "PREWISE_SANDBOX_API" in user_data
    assert "PREWISE_SANDBOX_TOKEN" in user_data
    assert "agent-secret" in user_data
    assert "SetEnvironmentVariable('PREWISE_SANDBOX_TOKEN'" not in user_data
    assert "SetEnvironmentVariable('PREWISE_SANDBOX_API'" not in user_data
    assert "PrewiseSandboxAgent.ps1" in user_data
    assert "/bootstrap" in user_data
    assert "X-Sandbox-Agent-Token" in user_data
    assert "Invoke-WebRequest" in user_data
    bootstrap_expression = re.search(r"\$bootstrapUrl=(.*?);", user_data)
    assert bootstrap_expression is not None
    assert "agent-secret" not in bootstrap_expression.group(1)
    assert len(user_data.encode("utf-8")) <= 16_384
    assert fake.run_params["MetadataOptions"]["HttpProtocolIpv6"] == "disabled"
    assert fake.run_params["MetadataOptions"]["InstanceMetadataTags"] == "disabled"


def test_failed_aws_waiter_terminates_the_started_instance(monkeypatch) -> None:
    _configure(monkeypatch)
    fake = FakeEC2(waiter_error=RuntimeError("waiter failed"))
    service = CloudSandboxService()
    monkeypatch.setattr(service, "_client", lambda: fake)

    with pytest.raises(RuntimeError, match="waiter failed"):
        service.provision(
            "session-456",
            "user-456",
            "2026-07-18T18:30:00+00:00",
            "pro",
            "agent-secret",
        )

    assert fake.terminated == ["i-test123"]
    assert fake.waiters["instance_terminated"].calls


def test_failed_provider_cleanup_retains_instance_id_for_reconciliation(
    monkeypatch,
) -> None:
    _configure(monkeypatch)
    fake = FakeEC2(
        waiter_error=RuntimeError("waiter failed"),
        termination_waiter_error=RuntimeError("termination waiter failed"),
    )
    service = CloudSandboxService()
    monkeypatch.setattr(service, "_client", lambda: fake)

    with pytest.raises(CloudSandboxProvisioningError) as raised:
        service.provision(
            "session-reconcile",
            "user-reconcile",
            "2026-07-18T18:30:00+00:00",
            "pro",
            "agent-secret",
        )

    assert raised.value.instance_id == "i-test123"
    assert raised.value.cleanup_confirmed is False


def test_cleanup_can_find_instances_by_durable_session_tag(monkeypatch) -> None:
    _configure(monkeypatch)
    fake = FakeEC2(
        describe_response={
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-orphan-b"},
                        {"InstanceId": "i-orphan-a"},
                    ]
                }
            ]
        }
    )
    service = CloudSandboxService()
    monkeypatch.setattr(service, "_client", lambda: fake)

    found = service.terminate_session_instances("session-restart")

    assert found == ["i-orphan-a", "i-orphan-b"]
    assert fake.terminated == found
    assert fake.describe_calls[0]["Filters"][0] == {
        "Name": "tag:PrewiseSession",
        "Values": ["session-restart"],
    }


def test_agent_callback_must_be_https_even_outside_production(monkeypatch) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "sandbox_public_base_url", "http://api.example.test")

    status = CloudSandboxService().availability("pro", "auto")

    assert status == {
        "available": False,
        "reason": "invalid_agent_callback",
        "missing": [],
    }


def test_tier_configuration_requires_the_matching_ami(monkeypatch) -> None:
    _configure(monkeypatch)
    service = CloudSandboxService()

    assert service.configured("pro") is True
    assert service.configured("max") is True

    monkeypatch.setattr(settings, "aws_sandbox_max_ami_id", "")
    assert service.configured("pro") is True
    assert service.configured("max") is False


def test_interactive_uses_dedicated_private_worker_and_configured_broker(
    monkeypatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "aws_sandbox_interactive_ami_id", "ami-interactive")
    monkeypatch.setattr(
        settings,
        "aws_sandbox_interactive_security_group_id",
        "sg-interactive-private",
    )
    monkeypatch.setattr(
        settings,
        "sandbox_remote_broker_url_template",
        "https://broker.example.test/connect/{session_id}/{instance_id}",
    )
    monkeypatch.setattr(settings, "sandbox_remote_broker_secret", "b" * 40)
    monkeypatch.setattr(
        settings,
        "sandbox_remote_broker_health_url",
        "https://broker.example.test/healthz",
    )
    fake = FakeEC2()
    service = CloudSandboxService()
    monkeypatch.setattr(service, "_client", lambda: fake)
    monkeypatch.setattr(service, "_broker_health_status", lambda _url: (True, None))

    instance_id, remote_url = service.provision(
        "session interactive",
        "user-123",
        "2026-07-18T18:30:00+00:00",
        "pro",
        "agent-secret",
        "interactive",
        5,
    )

    assert instance_id == "i-test123"
    assert remote_url == (
        "https://broker.example.test/connect/session%20interactive/i-test123"
    )
    assert fake.run_params is not None
    assert fake.run_params["ImageId"] == "ami-interactive"
    interface = fake.run_params["NetworkInterfaces"][0]
    assert interface["Groups"] == ["sg-interactive-private"]
    assert interface["AssociatePublicIpAddress"] is False
    tags = fake.run_params["TagSpecifications"][0]["Tags"]
    assert {"Key": "SandboxMode", "Value": "interactive"} in tags
    assert {"Key": "LeaseMinutes", "Value": "5"} in tags


def test_interactive_availability_is_fail_visible(monkeypatch) -> None:
    _configure(monkeypatch)
    service = CloudSandboxService()

    status = service.availability("pro", "interactive")

    assert status["available"] is False
    assert status["reason"] == "missing_configuration"
    assert "ami" in status["missing"]
    assert "security_group" in status["missing"]
    assert "remote_url_source" in status["missing"]
    assert "broker_secret" in status["missing"]


def test_browser_access_url_uses_opaque_token_not_rdp_credentials() -> None:
    service = CloudSandboxService()

    url = service.browser_access_url(
        "https://broker.example.test/connect?view=desktop",
        session_id="session-123",
        access_token="opaque-browser-token",
    )

    assert "prewise_session=session-123" in url
    assert "prewise_access_token=opaque-browser-token" in url
    assert "username" not in url
    assert "password" not in url

    with pytest.raises(RuntimeError, match="credential"):
        service.browser_access_url(
            "https://broker.example.test/connect?password=rdp-secret",
            session_id="session-123",
            access_token="opaque-browser-token",
        )
