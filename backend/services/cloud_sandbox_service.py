"""Provision and terminate disposable Windows EC2 sandbox instances."""

from __future__ import annotations

import json
import logging
import threading
import time
from string import Formatter
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from backend.config import settings

logger = logging.getLogger(__name__)

BROKER_HEALTH_TIMEOUT_SECONDS = 2.0
BROKER_HEALTH_CACHE_SECONDS = 10.0
BROKER_HEALTH_MAX_BYTES = 16 * 1024
BROKER_HEALTH_PROTOCOL_VERSION = "1"
BROKER_HEALTH_CAPABILITIES = {
    "lease_enforcement",
    "one_time_token_consume",
    "remote_desktop",
}


class _RejectRedirects(HTTPRedirectHandler):
    """Health checks never follow redirects to a different trust boundary."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class CloudSandboxProvisioningError(RuntimeError):
    """Provisioning failed after EC2 may already have created an instance."""

    def __init__(
        self,
        message: str,
        *,
        instance_id: str,
        cleanup_confirmed: bool,
    ) -> None:
        super().__init__(message)
        self.instance_id = instance_id
        self.cleanup_confirmed = cleanup_confirmed


class CloudSandboxService:
    _broker_health_cache: dict[str, tuple[float, bool, str | None]] = {}
    _broker_health_lock = threading.Lock()

    def _client(self):
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("Chưa cài boto3 cho AWS sandbox") from exc
        credentials = {}
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            credentials = {
                "aws_access_key_id": settings.aws_access_key_id,
                "aws_secret_access_key": settings.aws_secret_access_key,
            }
            if settings.aws_session_token:
                credentials["aws_session_token"] = settings.aws_session_token
        return boto3.client("ec2", region_name=settings.aws_region, **credentials)

    @staticmethod
    def _image_id(tier: str, mode: str) -> str:
        if mode == "interactive":
            return (
                settings.aws_sandbox_interactive_max_ami_id
                if tier == "max"
                else settings.aws_sandbox_interactive_ami_id
            )
        return (
            settings.aws_sandbox_max_ami_id
            if tier == "max"
            else settings.aws_sandbox_ami_id
        )

    @staticmethod
    def _instance_type(tier: str, mode: str) -> str:
        if mode == "interactive":
            return (
                settings.aws_sandbox_interactive_max_instance_type
                if tier == "max"
                else settings.aws_sandbox_interactive_instance_type
            )
        return (
            settings.aws_sandbox_max_instance_type
            if tier == "max"
            else settings.aws_sandbox_instance_type
        )

    @staticmethod
    def _security_group_id(mode: str) -> str:
        return (
            settings.aws_sandbox_interactive_security_group_id
            if mode == "interactive"
            else settings.aws_sandbox_security_group_id
        )

    def availability(self, tier: str = "pro", mode: str = "auto") -> dict:
        """Describe availability without pretending a remote desktop exists."""
        if tier not in {"pro", "max"}:
            return {"available": False, "reason": "unsupported_tier", "missing": []}
        if mode not in {"auto", "interactive"}:
            return {"available": False, "reason": "invalid_mode", "missing": []}
        required = {
            "ami": self._image_id(tier, mode),
            "subnet": settings.aws_sandbox_subnet_id,
            "security_group": self._security_group_id(mode),
            "agent_callback": settings.sandbox_public_base_url,
        }
        if mode == "interactive":
            required.update(
                {
                    "remote_url_source": (
                        settings.sandbox_remote_broker_url_template
                        or settings.aws_sandbox_remote_url_tag
                    ),
                    "broker_secret": settings.sandbox_remote_broker_secret,
                    "broker_health": settings.sandbox_remote_broker_health_url,
                }
            )
        missing = [name for name, value in required.items() if not value]
        if missing:
            return {
                "available": False,
                "reason": "missing_configuration",
                "missing": missing,
            }
        callback = urlsplit(settings.sandbox_public_base_url.strip())
        if (
            callback.scheme != "https"
            or not callback.hostname
            or callback.username
            or callback.password
            or callback.query
            or callback.fragment
        ):
            return {
                "available": False,
                "reason": "invalid_agent_callback",
                "missing": [],
            }
        if mode == "interactive" and not (
            15 <= settings.sandbox_remote_access_token_ttl_seconds <= 300
        ):
            return {
                "available": False,
                "reason": "invalid_token_ttl",
                "missing": [],
            }
        if mode == "interactive":
            broker = self.broker_availability()
            if not broker["available"]:
                return broker
        return {"available": True, "reason": None, "missing": []}

    def broker_availability(self) -> dict:
        """Validate the adapter contract and cached liveness for active sessions."""

        template = settings.sandbox_remote_broker_url_template.strip()
        tag_name = settings.aws_sandbox_remote_url_tag.strip()
        required = {
            "remote_url_source": template or tag_name,
            "broker_secret": settings.sandbox_remote_broker_secret,
            "broker_health": settings.sandbox_remote_broker_health_url,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            return {
                "available": False,
                "reason": "missing_configuration",
                "missing": missing,
            }
        if len(settings.sandbox_remote_broker_secret.encode("utf-8")) < 32:
            return {
                "available": False,
                "reason": "weak_broker_secret",
                "missing": [],
            }
        if template and tag_name:
            return {
                "available": False,
                "reason": "ambiguous_remote_url_source",
                "missing": [],
            }
        if template:
            try:
                self._render_remote_url_template(
                    template,
                    session_id="preflight-session",
                    instance_id="i-preflight",
                )
            except RuntimeError:
                return {
                    "available": False,
                    "reason": "invalid_remote_url_template",
                    "missing": [],
                }
        try:
            health_url = self._validated_broker_health_url(
                settings.sandbox_remote_broker_health_url
            )
        except RuntimeError:
            return {
                "available": False,
                "reason": "invalid_broker_health_url",
                "missing": [],
            }
        broker_healthy, health_reason = self._broker_health_status(health_url)
        if not broker_healthy:
            return {
                "available": False,
                "reason": health_reason or "broker_unhealthy",
                "missing": [],
            }
        return {"available": True, "reason": None, "missing": []}

    def configured(self, tier: str = "pro", mode: str = "auto") -> bool:
        return bool(self.availability(tier, mode)["available"])

    @staticmethod
    def _powershell_literal(value: str) -> str:
        """Escape an administrator-controlled value for a PowerShell single-quoted literal."""
        return "'" + value.replace("'", "''") + "'"

    def _user_data(
        self,
        session_id: str,
        expires_iso: str,
        agent_token: str,
    ) -> str:
        """Bootstrap the agent and force OS shutdown when the paid session expires.

        EC2 is configured with ``InstanceInitiatedShutdownBehavior=terminate``;
        therefore the VM destroys itself even if the API process restarts after
        provisioning and loses its in-memory task.
        """
        expires = self._powershell_literal(expires_iso)
        lines = [
            "<powershell>",
            f"$expires=[DateTimeOffset]::Parse({expires});",
            "$remaining=[Math]::Max(60,[int][Math]::Ceiling(($expires-[DateTimeOffset]::UtcNow).TotalSeconds));",
            "Start-Process -FilePath shutdown.exe -ArgumentList @('/s','/t',\"$remaining\",'/c','Prewise Sandbox expired') -WindowStyle Hidden;",
        ]
        if settings.sandbox_public_base_url and agent_token:
            api_base = self._powershell_literal(
                settings.sandbox_public_base_url.rstrip("/")
            )
            session = self._powershell_literal(session_id)
            token = self._powershell_literal(agent_token)
            lines.extend(
                [
                    "$agentDir='C:\\Prewise'; New-Item -ItemType Directory -Path $agentDir -Force | Out-Null;",
                    f"$env:PREWISE_SANDBOX_API={api_base};",
                    f"$env:PREWISE_SANDBOX_SESSION={session};",
                    f"$env:PREWISE_SANDBOX_TOKEN={token};",
                    "$bootstrapUrl=$env:PREWISE_SANDBOX_API+'/v1/sandbox-cloud/agent/sessions/'+$env:PREWISE_SANDBOX_SESSION+'/bootstrap';",
                    "$headers=@{'X-Sandbox-Agent-Token'=$env:PREWISE_SANDBOX_TOKEN};$agentPath='C:\\Prewise\\PrewiseSandboxAgent.ps1';",
                    "for($attempt=0;$attempt -lt 30;$attempt++){try{Invoke-WebRequest -UseBasicParsing -Uri $bootstrapUrl -Headers $headers -OutFile $agentPath -TimeoutSec 15;if((Get-Item -LiteralPath $agentPath).Length -gt 0){break}}catch{};Start-Sleep -Seconds 10};",
                    "if(!(Test-Path -LiteralPath $agentPath)){throw 'Prewise agent bootstrap failed'};",
                    "Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\\Prewise\\PrewiseSandboxAgent.ps1') -WindowStyle Hidden;",
                ]
            )
        lines.append("</powershell>")
        return "".join(lines)

    @staticmethod
    def _validated_remote_url(value: str) -> str:
        """Accept only a credential-free HTTPS broker target."""
        parsed = urlsplit(value.strip())
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        allow_loopback_http = settings.app_env != "production" and loopback
        try:
            parsed.port
        except ValueError as exc:
            raise RuntimeError("Remote Sandbox broker có port không hợp lệ") from exc
        if not parsed.hostname or not (
            parsed.scheme == "https"
            or (parsed.scheme == "http" and allow_loopback_http)
        ):
            raise RuntimeError("Remote Sandbox broker phải dùng HTTPS")
        if parsed.username or parsed.password:
            raise RuntimeError("Remote Sandbox URL không được chứa thông tin đăng nhập")
        if (
            settings.app_env == "production"
            and parsed.hostname.lower().endswith(".trycloudflare.com")
        ):
            raise RuntimeError("Remote Sandbox production cần managed hostname ổn định")
        sensitive = {"token", "access_token", "password", "secret", "credential", "key"}
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
            normalized = name.lower().replace("-", "_")
            if normalized in {"prewise_session", "prewise_access_token"}:
                raise RuntimeError("Remote Sandbox URL chứa tham số handshake dành riêng")
            if normalized in sensitive or any(part in normalized for part in sensitive):
                raise RuntimeError("Remote Sandbox URL không được chứa credential")
        return urlunsplit(parsed)

    @classmethod
    def _render_remote_url_template(
        cls,
        template: str,
        *,
        session_id: str,
        instance_id: str,
    ) -> str:
        allowed_fields = {"session_id", "instance_id"}
        try:
            parsed_fields = Formatter().parse(template)
            for _literal, field_name, format_spec, conversion in parsed_fields:
                if field_name is None:
                    continue
                if (
                    field_name not in allowed_fields
                    or format_spec
                    or conversion is not None
                ):
                    raise RuntimeError(
                        "SANDBOX_REMOTE_BROKER_URL_TEMPLATE chỉ hỗ trợ "
                        "{session_id} và {instance_id}"
                    )
            value = template.format(
                session_id=quote(session_id, safe=""),
                instance_id=quote(instance_id, safe=""),
            )
        except (KeyError, ValueError) as exc:
            raise RuntimeError(
                "SANDBOX_REMOTE_BROKER_URL_TEMPLATE chỉ hỗ trợ "
                "{session_id} và {instance_id}"
            ) from exc
        return cls._validated_remote_url(value)

    @staticmethod
    def _validated_broker_health_url(value: str) -> str:
        parsed = urlsplit(value.strip())
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        allow_loopback_http = settings.app_env != "production" and loopback
        try:
            parsed.port
        except ValueError as exc:
            raise RuntimeError("Broker health URL có port không hợp lệ") from exc
        if not parsed.hostname or not (
            parsed.scheme == "https"
            or (parsed.scheme == "http" and allow_loopback_http)
        ):
            raise RuntimeError("Broker health endpoint phải dùng HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise RuntimeError("Broker health endpoint phải là URL không credential")
        if (
            settings.app_env == "production"
            and parsed.hostname.lower().endswith(".trycloudflare.com")
        ):
            raise RuntimeError("Broker health production cần managed hostname ổn định")
        return urlunsplit(parsed)

    @staticmethod
    def _validate_broker_health_payload(payload: object) -> tuple[bool, str | None]:
        if not isinstance(payload, dict):
            return False, "broker_health_invalid_contract"
        capabilities = payload.get("capabilities")
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) for item in capabilities
        ):
            return False, "broker_health_invalid_contract"
        if (
            payload.get("status") not in {"ok", "healthy"}
            or payload.get("ready") is not True
            or str(payload.get("protocolVersion"))
            != BROKER_HEALTH_PROTOCOL_VERSION
            or not BROKER_HEALTH_CAPABILITIES.issubset(set(capabilities))
        ):
            return False, "broker_health_not_ready"
        return True, None

    @classmethod
    def _probe_broker_health(cls, health_url: str) -> tuple[bool, str | None]:
        request = Request(
            health_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "Prewise-Interactive-Preflight/1",
            },
            method="GET",
        )
        opener = build_opener(ProxyHandler({}), _RejectRedirects())
        try:
            with opener.open(
                request,
                timeout=BROKER_HEALTH_TIMEOUT_SECONDS,
            ) as response:
                if response.status != 200:
                    return False, f"broker_health_http_{response.status}"
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    return False, "broker_health_invalid_content_type"
                raw = response.read(BROKER_HEALTH_MAX_BYTES + 1)
        except HTTPError as exc:
            return False, f"broker_health_http_{exc.code}"
        except (TimeoutError, URLError, OSError):
            return False, "broker_health_unreachable"
        if len(raw) > BROKER_HEALTH_MAX_BYTES:
            return False, "broker_health_response_too_large"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "broker_health_invalid_json"
        return cls._validate_broker_health_payload(payload)

    @classmethod
    def _broker_health_status(cls, health_url: str) -> tuple[bool, str | None]:
        now = time.monotonic()
        with cls._broker_health_lock:
            cached = cls._broker_health_cache.get(health_url)
            if cached and now - cached[0] < BROKER_HEALTH_CACHE_SECONDS:
                return cached[1], cached[2]
        healthy, reason = cls._probe_broker_health(health_url)
        with cls._broker_health_lock:
            cls._broker_health_cache[health_url] = (now, healthy, reason)
        return healthy, reason

    @classmethod
    def clear_broker_health_cache(cls) -> None:
        """Reset the bounded liveness cache (primarily for tests/deploy hooks)."""

        with cls._broker_health_lock:
            cls._broker_health_cache.clear()

    def _remote_url_from_ready_instance(
        self,
        instance: dict,
        *,
        session_id: str,
        instance_id: str,
    ) -> str:
        template = settings.sandbox_remote_broker_url_template.strip()
        if template:
            return self._render_remote_url_template(
                template,
                session_id=session_id,
                instance_id=instance_id,
            )
        else:
            tag_name = settings.aws_sandbox_remote_url_tag.strip()
            tags = {
                str(tag.get("Key", "")): str(tag.get("Value", ""))
                for tag in instance.get("Tags", [])
            }
            value = tags.get(tag_name, "")
            if not value:
                raise RuntimeError(
                    f"EC2 chưa công bố remote URL qua tag {tag_name!r}"
                )
        return self._validated_remote_url(value)

    def browser_access_url(
        self,
        remote_url: str,
        *,
        session_id: str,
        access_token: str,
    ) -> str:
        """Create a direct browser URL from a configured broker target.

        The opaque token authorizes only the broker handshake. It is not an RDP
        username/password and the raw value is never persisted by Prewise.
        """
        parsed = urlsplit(self._validated_remote_url(remote_url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.extend(
            [
                ("prewise_session", session_id),
                ("prewise_access_token", access_token),
            ]
        )
        return urlunsplit(parsed._replace(query=urlencode(query)))

    def provision(
        self,
        session_id: str,
        user_id: str,
        expires_iso: str,
        tier: str = "pro",
        agent_token: str = "",
        mode: str = "auto",
        lease_minutes: int = 10,
    ) -> tuple[str, str]:
        availability = self.availability(tier, mode)
        if not availability["available"]:
            detail = ", ".join(availability["missing"]) or availability["reason"]
            raise RuntimeError(
                f"AWS Sandbox {tier.upper()} {mode} chưa sẵn sàng: {detail}"
            )
        params = {
            "ImageId": self._image_id(tier, mode),
            "InstanceType": self._instance_type(tier, mode),
            "MinCount": 1,
            "MaxCount": 1,
            # Production workers stay private and use controlled NAT/proxy
            # egress. A public address is an explicit development/demo escape
            # hatch for test accounts in subnets that do not yet have NAT; the
            # security group remains authoritative and no inbound rule is added.
            "NetworkInterfaces": [
                {
                    "DeviceIndex": 0,
                    "SubnetId": settings.aws_sandbox_subnet_id,
                    "Groups": [self._security_group_id(mode)],
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
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "Encrypted": True,
                        "VolumeType": "gp3",
                    },
                }
            ],
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"prewise-sandbox-{session_id[:8]}"},
                        {"Key": "ManagedBy", "Value": "PrewiseSandbox"},
                        {"Key": "PrewiseSession", "Value": session_id},
                        {"Key": "PrewiseUser", "Value": user_id},
                        {"Key": "SandboxTier", "Value": tier},
                        {"Key": "SandboxMode", "Value": mode},
                        {"Key": "LeaseMinutes", "Value": str(lease_minutes)},
                        {"Key": "ExpiresAt", "Value": expires_iso},
                    ],
                }
            ],
            "UserData": self._user_data(session_id, expires_iso, agent_token),
            # Retrying the same session after a transient API error must never
            # launch a second paid worker.
            "ClientToken": f"prewise-{session_id}",
        }
        if settings.aws_sandbox_key_name:
            params["KeyName"] = settings.aws_sandbox_key_name

        ec2 = self._client()
        instance_id = ec2.run_instances(**params)["Instances"][0]["InstanceId"]
        try:
            waiter = ec2.get_waiter("instance_running")
            waiter.wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 5, "MaxAttempts": 48},
            )
            ready_waiter = ec2.get_waiter("instance_status_ok")
            ready_waiter.wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 5, "MaxAttempts": 48},
            )
            instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][
                0
            ]["Instances"][0]
            remote_url = ""
            if mode == "interactive":
                remote_url = self._remote_url_from_ready_instance(
                    instance,
                    session_id=session_id,
                    instance_id=instance_id,
                )
        except Exception as exc:
            cleanup_confirmed = False
            try:
                ec2.terminate_instances(InstanceIds=[instance_id])
                terminated_waiter = ec2.get_waiter("instance_terminated")
                terminated_waiter.wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 5, "MaxAttempts": 48},
                )
                cleanup_confirmed = True
            except Exception:  # pragma: no cover - secondary AWS recovery failure
                logger.exception(
                    "Could not terminate failed sandbox instance %s", instance_id
                )
            raise CloudSandboxProvisioningError(
                str(exc),
                instance_id=instance_id,
                cleanup_confirmed=cleanup_confirmed,
            ) from exc

        # Auto mode is always agent-only and deliberately returns no remote URL.
        # Interactive mode receives a credential-free broker target only after
        # both EC2 status checks have completed.
        return instance_id, remote_url

    def terminate(self, instance_id: str) -> None:
        if instance_id:
            ec2 = self._client()
            ec2.terminate_instances(InstanceIds=[instance_id])
            waiter = ec2.get_waiter("instance_terminated")
            waiter.wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 5, "MaxAttempts": 48},
            )

    def terminate_session_instances(self, session_id: str) -> list[str]:
        """Find and terminate every live EC2 worker carrying a session tag.

        This is the restart-safe path for the narrow window after RunInstances
        succeeds but before the API has persisted ``provider_instance_id``.
        Tags are attached atomically at launch, and ClientToken prevents a retry
        from creating a second worker.
        """
        ec2 = self._client()
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:PrewiseSession", "Values": [session_id]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        )
        instance_ids = sorted(
            {
                str(instance.get("InstanceId", ""))
                for reservation in response.get("Reservations", [])
                for instance in reservation.get("Instances", [])
                if instance.get("InstanceId")
            }
        )
        if not instance_ids:
            return []
        ec2.terminate_instances(InstanceIds=instance_ids)
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(
            InstanceIds=instance_ids,
            WaiterConfig={"Delay": 5, "MaxAttempts": 48},
        )
        return instance_ids


cloud_sandbox_service = CloudSandboxService()
