from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT_PATH = ROOT / "server" / "sandbox-agent" / "PrewiseSandboxAgent.ps1"


@pytest.fixture(scope="module")
def agent_script() -> str:
    return AGENT_PATH.read_text(encoding="utf-8")


def _function_body(script: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^function\s+{re.escape(name)}\b.*?(?=^function\s+|^Set-AnalysisPhase\s+'agent_started')",
        script,
    )
    assert match is not None, f"missing PowerShell function: {name}"
    return match.group(0)


def test_agent_supports_safe_dual_mode_contract(agent_script: str) -> None:
    assert "X-Sandbox-Mode" in agent_script
    assert "X-Sandbox-Lease-Seconds" in agent_script
    assert "$analysisMode = 'auto'" in agent_script
    assert "if ($analysisMode -eq 'interactive')" in agent_script
    assert "Send-ProgressReport 'staged'" in agent_script

    auto_body = _function_body(agent_script, "Invoke-AutoAnalysis")
    interactive_body = _function_body(agent_script, "Invoke-InteractiveAnalysis")
    assert "Start-SandboxProcess" in auto_body
    assert "Initialize-SamplePrincipal" in auto_body
    assert "Start-SandboxProcess" not in interactive_body
    assert "Find-InteractiveRoots" in interactive_body

    # Automatic execution is always 60-120 seconds. Interactive mode consumes
    # the server's remaining lease without rounding values such as 297 up to 300.
    assert re.search(
        r"Get-BoundedInteger\s+\(\[string\]\$env:PREWISE_SANDBOX_EXECUTION_TIMEOUT_SECONDS\)\s+90\s+60\s+120",
        agent_script,
    )
    assert re.search(
        r"Get-BoundedInteger\s+\(\[string\]\$env:PREWISE_SANDBOX_DOWNLOAD_TIMEOUT_SECONDS\)\s+900\s+30\s+1800",
        agent_script,
    )
    assert re.search(
        r"Get-BoundedInteger\s+\(\[string\]\$response\.Headers\['X-Sandbox-Lease-Seconds'\]\)\s+300\s+1\s+600",
        agent_script,
    )
    assert "interactiveLeaseDeadlineUtc = [DateTime]::UtcNow.AddSeconds" in agent_script
    assert "observationDeadlineUtc = $leaseDeadlineUtc" in agent_script
    assert "finalizationMarginSeconds = 0" in agent_script
    assert "interactive_lease_elapsed" in agent_script


def test_agent_collects_bounded_attributable_evidence(agent_script: str) -> None:
    required_contracts = (
        "Get-CimInstance -ClassName Win32_Process",
        "Get-WmiObject -Class Win32_Process",
        "parent_pid",
        "executable_path",
        "command_line",
        "Get-RedactedCommandLine",
        "Compare-FileSnapshots",
        "Get-RegistrySnapshot",
        "Registry::HKEY_USERS",
        "knownUserRegistryHives",
        "baseline_only",
        "PERSISTENCE_REGISTRY_CHANGED",
        "Get-NetTCPConnection",
        "System32\\netstat.exe",
        "$script:observedPids.Contains($ownerId)",
        "EXTERNAL_NETWORK_CONNECTION",
        "screenshot_metadata",
        "pixels_exported = $false",
        "first_seen_utc",
        "last_seen_utc",
        "Get-RiskAssessment",
    )
    for contract in required_contracts:
        assert contract in agent_script

    assert "    image = $image" not in agent_script

    assert "$maxProcesses = 100" in agent_script
    assert "$maxFileEvents = 200" in agent_script
    assert "$maxRegistryEvents = 200" in agent_script
    assert "$maxNetworkEvents = 200" in agent_script
    assert "$maxSnapshotFiles = 512" in agent_script
    assert "Limit-ReportArray" in agent_script
    limit_body = _function_body(agent_script, "Limit-ReportArray")
    assert "return ,@()" in limit_body
    assert "return ,@($values)" in limit_body
    assert "return ,@($values[0..($limit - 1)])" in limit_body


def test_auto_collector_prioritizes_durable_evidence_and_never_loses_root(
    agent_script: str,
) -> None:
    poll_body = _function_body(agent_script, "Invoke-TelemetryPoll")
    assert poll_body.index("Get-FileSnapshot") < poll_body.index("Get-CurrentProcessMap")
    assert poll_body.index("Get-RegistrySnapshot") < poll_body.index("Get-CurrentProcessMap")

    process_map_body = _function_body(agent_script, "Get-CurrentProcessMap")
    assert "Get-Command Get-CimInstance" in process_map_body
    assert "Get-WmiObject -Class Win32_Process" in process_map_body

    auto_body = _function_body(agent_script, "Invoke-AutoAnalysis")
    assert "Add-ObservedProcess $rootProcessItem 'auto-root-launch'" in auto_body
    assert auto_body.index("Add-ObservedProcess $rootProcessItem") < auto_body.index("while ([DateTime]::UtcNow")
    assert "SAMPLE_NONZERO_EXIT" in auto_body
    assert "execution_failed = $executionFailed" in auto_body
    assert "root_exit_code = $rootExitCode" in auto_body
    assert "Reset-TelemetryHealth" in auto_body

    assessment_body = _function_body(agent_script, "Get-RiskAssessment")
    assert "analysis_inconclusive_telemetry_degraded" in assessment_body
    assert "Get-DegradedTelemetrySummary" in assessment_body

    process_map_body = _function_body(agent_script, "Get-CurrentProcessMap")
    assert "$script:telemetryHealth.processes = $true" in process_map_body
    file_snapshot_body = _function_body(agent_script, "Get-FileSnapshot")
    assert "$script:telemetryHealth.files = $true" in file_snapshot_body
    registry_snapshot_body = _function_body(agent_script, "Get-RegistrySnapshot")
    assert "$script:telemetryHealth.registry = $true" in registry_snapshot_body
    network_body = _function_body(agent_script, "Capture-NetworkTelemetry")
    assert "$script:telemetryHealth.network = $true" in network_body

    registry_body = _function_body(agent_script, "Get-RegistrySnapshot")
    assert "$analysisMode -eq 'auto'" in registry_body
    assert "$script:sampleAccountSid" in registry_body


def test_agent_does_not_export_secrets_or_evidence_contents(agent_script: str) -> None:
    start_body = _function_body(agent_script, "Start-SandboxProcess")
    assert "PREWISE_SANDBOX_" in start_body
    assert "AWS_SECRET" in start_body
    assert "EnvironmentVariables.Remove" in start_body
    assert "$startInfo.UserName = $sampleAccountName" in start_body
    assert "$startInfo.Password = $script:sampleAccountSecurePassword" in start_body
    assert "$startInfo.LoadUserProfile = $true" in start_body

    principal_body = _function_body(agent_script, "Initialize-SamplePrincipal")
    account_api_body = _function_body(agent_script, "Initialize-LocalAccountApi")
    assert "NetUserAdd" in account_api_body
    assert "NetUserDel" in account_api_body
    assert "NetLocalGroupAddMembers" in account_api_body
    assert "USER_PRIV_USER" in account_api_body
    assert "[ADSI]" not in principal_body
    assert "CreateStandardUser" in principal_body
    assert "AddToLocalGroup" in principal_body
    assert "S-1-5-32-545" in principal_body
    assert "net.exe" not in principal_body
    assert "[Array]::Clear($randomBytes" in principal_body
    assert "$plainPassword = $null" in principal_body

    metadata_body = _function_body(agent_script, "Initialize-MetadataIsolation")
    assert "169.254.169.254" in metadata_body
    assert "action=block" in metadata_body

    redaction_body = _function_body(agent_script, "Get-RedactedCommandLine")
    for sensitive_key in ("password", "token", "secret", "credential", "api[_-]?key"):
        assert sensitive_key in redaction_body
    assert "[REDACTED]" in redaction_body
    assert "command_line_redacted" in agent_script

    final_report_body = _function_body(agent_script, "Send-FinalReport")
    assert "$token" not in final_report_body
    assert "PREWISE_SANDBOX_TOKEN" not in final_report_body
    assert "file_contents" not in final_report_body
    assert "registry_value_data" not in final_report_body

    assert "raw_value_exported = $false" in agent_script
    assert "content_exported = $false" in agent_script
    assert "Remove-Item -LiteralPath $screenshotPath" in agent_script
    assert "Get-SafeExceptionCode" in agent_script


def test_agent_has_fail_safe_reporting_and_cleanup(agent_script: str) -> None:
    submit_body = _function_body(agent_script, "Submit-ReportBody")
    assert "$attemptLimit = if ($throwOnFailure) { 2 } else { 1 }" in submit_body
    assert "$attempt -le $attemptLimit" in submit_body
    assert "-TimeoutSec 4" in submit_body
    assert "Invoke-RestMethod -Method Post" in submit_body

    assert "catch {" in agent_script
    assert "Send-FinalReport 'failed' 'analysis_failed'" in agent_script
    assert "finally {" in agent_script
    assert "Stop-ObservedProcesses" in agent_script
    assert "Remove-SamplePrincipal" in agent_script
    assert "Remove-WorkingDirectories" in agent_script
    assert "$headers.Clear()" in agent_script
    assert "$token = $null" in agent_script


def test_agent_is_valid_powershell_when_parser_is_available() -> None:
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("Windows PowerShell parser is not available")

    escaped_path = str(AGENT_PATH).replace("'", "''")
    command = (
        "$tokens=$null; $errors=$null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped_path}',"
        "[ref]$tokens,[ref]$errors) | Out-Null; "
        "if($errors.Count){$errors | ForEach-Object {$_.Message}; exit 1}"
    )
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_local_account_native_api_compiles_when_powershell_is_available() -> None:
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("Windows PowerShell is not available")

    escaped_path = str(AGENT_PATH).replace("'", "''")
    command = (
        f"$source=[IO.File]::ReadAllText('{escaped_path}'); "
        "$tokens=$null; $errors=$null; "
        "$ast=[System.Management.Automation.Language.Parser]::ParseInput("
        "$source,[ref]$tokens,[ref]$errors); "
        "$fn=$ast.Find({param($node) "
        "$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Initialize-LocalAccountApi'},$true); "
        "if($null -eq $fn){throw 'missing native API initializer'}; "
        "Invoke-Expression $fn.Extent.Text; Initialize-LocalAccountApi; "
        "if($null -eq ('PrewiseSandboxNative.LocalAccounts' -as [type])){exit 1}"
    )
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_risk_assessment_fails_closed_when_telemetry_is_degraded() -> None:
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("Windows PowerShell is not available")

    escaped_path = str(AGENT_PATH).replace("'", "''")
    command = (
        f"$source=[IO.File]::ReadAllText('{escaped_path}'); "
        "$tokens=$null; $errors=$null; "
        "$ast=[System.Management.Automation.Language.Parser]::ParseInput("
        "$source,[ref]$tokens,[ref]$errors); "
        "foreach($name in @('Get-DegradedTelemetrySummary','Get-RiskAssessment')){"
        "$fn=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq $name},$true); "
        "if($null -eq $fn){throw ('missing '+$name)}; Invoke-Expression $fn.Extent.Text}; "
        "$script:telemetryHealth=[ordered]@{processes=$true;files=$false;registry=$true;network=$true}; "
        "$script:riskSignals=[ordered]@{}; $analysisMode='auto'; "
        "Get-RiskAssessment $true $false $false | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assessment = json.loads(result.stdout)
    assert assessment["verdict"] == "analysis_inconclusive_telemetry_degraded"
    assert assessment["risk_score"] == 0
