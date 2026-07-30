from __future__ import annotations

import asyncio
import base64
import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime


class WindowsCredentialError(RuntimeError):
    pass


@dataclass(frozen=True)
class RdpCredential:
    hostname: str
    username: str
    password: str


def _random_password(length: int = 32) -> str:
    # Guarantee all Windows complexity classes; punctuation is intentionally
    # limited because the value crosses PowerShell and RDP configuration layers.
    alphabet = string.ascii_letters + string.digits + "!@#_-"
    value = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#_-"),
    ]
    value.extend(secrets.choice(alphabet) for _ in range(length - len(value)))
    secrets.SystemRandom().shuffle(value)
    return "".join(value)


def _encoded_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


class SsmEphemeralRdpManager:
    """Creates a lease-bound Windows user without persisting its password.

    The cleanup task is registered inside Windows before credentials are
    returned. This makes the lease boundary survive broker restarts.
    """

    def __init__(self, region: str, timeout_seconds: int = 90, *, ssm=None, ec2=None) -> None:
        if ssm is None or ec2 is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - deployment dependency
                raise WindowsCredentialError("boto3 is required by the broker") from exc
            ssm = ssm or boto3.client("ssm", region_name=region)
            ec2 = ec2 or boto3.client("ec2", region_name=region)
        self.ssm = ssm
        self.ec2 = ec2
        self.timeout_seconds = timeout_seconds

    def _run(self, instance_id: str, script: str) -> str:
        encoded = _encoded_powershell(script)
        response = self.ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            TimeoutSeconds=self.timeout_seconds,
            Parameters={
                "commands": [
                    f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"
                ]
            },
        )
        command_id = response["Command"]["CommandId"]
        waiter = self.ssm.get_waiter("command_executed")
        waiter.wait(
            CommandId=command_id,
            InstanceId=instance_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, self.timeout_seconds // 2)},
        )
        result = self.ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        if result.get("Status") != "Success":
            raise WindowsCredentialError("Windows credential command failed")
        return str(result.get("StandardOutputContent", "")).strip()

    async def create(
        self,
        instance_id: str,
        session_id: str,
        lease_expires_at: datetime,
    ) -> RdpCredential:
        lease = lease_expires_at.astimezone(UTC)
        remaining = int((lease - datetime.now(UTC)).total_seconds())
        if remaining < 15:
            raise WindowsCredentialError("Interactive lease is too close to expiry")
        username = f"pw_{session_id.replace('-', '')[:12]}"
        password = _random_password()
        cleanup_at = lease.strftime("%Y-%m-%dT%H:%M:%SZ")
        task_name = f"PrewiseLease-{username}"
        cleanup_script = f"""
$user = '{username}'
quser 2>$null | Select-String $user | ForEach-Object {{
  $parts = ($_ -split '\\s+') | Where-Object {{ $_ }}
  foreach ($part in $parts) {{ if ($part -match '^\\d+$') {{ logoff $part; break }} }}
}}
Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '{task_name}' -Confirm:$false -ErrorAction SilentlyContinue
"""
        cleanup_encoded = _encoded_powershell(cleanup_script)
        # Values contain only broker-generated restricted alphabets. The task
        # first logs off every matching interactive session, then deletes the
        # disposable account and itself.
        script = f"""
$ErrorActionPreference = 'Stop'
$user = '{username}'
$password = ConvertTo-SecureString '{password}' -AsPlainText -Force
if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {{ Remove-LocalUser -Name $user }}
New-LocalUser -Name $user -Password $password -AccountNeverExpires -PasswordNeverExpires | Out-Null
$rdpGroup = Get-LocalGroup -SID 'S-1-5-32-555'
Add-LocalGroupMember -Group $rdpGroup -Member $user
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoLogo -NoProfile -NonInteractive -EncodedCommand {cleanup_encoded}'
$cleanupAtUtc = [DateTime]::Parse('{cleanup_at}').ToUniversalTime()
$delaySeconds = [Math]::Max(1, [Math]::Floor(($cleanupAtUtc - [DateTime]::UtcNow).TotalSeconds))
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($delaySeconds)
Register-ScheduledTask -TaskName '{task_name}' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Write-Output 'READY'
"""
        output = await asyncio.to_thread(self._run, instance_id, script)
        if output.splitlines()[-1:] != ["READY"]:
            raise WindowsCredentialError("Windows did not confirm credential creation")
        response = await asyncio.to_thread(
            self.ec2.describe_instances,
            InstanceIds=[instance_id],
        )
        try:
            instance = response["Reservations"][0]["Instances"][0]
            hostname = str(
                instance.get("PrivateDnsName") or instance["PrivateIpAddress"]
            )
        except (KeyError, IndexError) as exc:
            await self.revoke(instance_id, username)
            raise WindowsCredentialError("Windows private address is unavailable") from exc
        return RdpCredential(hostname=hostname, username=username, password=password)

    async def revoke(self, instance_id: str, username: str) -> None:
        if not username.startswith("pw_") or not username[3:].isalnum():
            raise WindowsCredentialError("Refusing to revoke an unmanaged account")
        task_name = f"PrewiseLease-{username}"
        script = f"""
$user = '{username}'
quser 2>$null | Select-String $user | ForEach-Object {{
  $parts = ($_ -split '\\s+') | Where-Object {{ $_ }}
  foreach ($part in $parts) {{ if ($part -match '^\\d+$') {{ logoff $part; break }} }}
}}
Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '{task_name}' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output 'REVOKED'
"""
        await asyncio.to_thread(self._run, instance_id, script)
