# Prewise disposable Windows sandbox agent v2.
#
# This script belongs ONLY in a hardened, single-use Windows AMI. It stages one
# user-consented sample and supports two server-selected modes:
#   auto        - execute the sample for a bounded 60-120 seconds.
#   interactive - never auto-execute; observe a bounded 5-10 minute lease while
#                 an authenticated remote user may launch the staged sample.
#
# The agent reports metadata and hashes only. It never reports file contents,
# registry values, environment secrets, screenshots, or the agent token.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$api = ([string]$env:PREWISE_SANDBOX_API).TrimEnd('/')
$session = [string]$env:PREWISE_SANDBOX_SESSION
$token = [string]$env:PREWISE_SANDBOX_TOKEN
if ([string]::IsNullOrWhiteSpace($api) -or
    [string]::IsNullOrWhiteSpace($session) -or
    [string]::IsNullOrWhiteSpace($token)) {
  throw 'Missing Prewise sandbox agent configuration.'
}

$headers = @{ 'X-Sandbox-Agent-Token' = $token }
$sampleDir = 'C:\Prewise\Sample'
$evidenceDir = 'C:\Prewise\Evidence'
$downloadPath = Join-Path $sampleDir 'sample.download'
$samplePath = $null
$sampleSha256 = $null
$analysisMode = 'auto'
$interactiveLeaseSeconds = 300
$interactiveLeaseDeadlineUtc = $null
$sampleAccountName = 'PrewiseSample'
$script:sampleAccountSecurePassword = $null
$script:sampleAccountSid = $null
$allowedExtensions = @('.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.ps1')
$executableArtifactExtensions = @('.exe', '.dll', '.msi', '.bat', '.cmd', '.com', '.scr', '.ps1', '.vbs', '.js', '.hta')

# These match the current gateway schema limits. Keeping the limits here also
# ensures a noisy sample cannot create an unbounded JSON report.
$maxProcesses = 100
$maxFileEvents = 200
$maxRegistryEvents = 200
$maxNetworkEvents = 200
$maxSnapshotFiles = 512

$script:phaseTimestamps = [ordered]@{}
$script:currentPhase = 'initializing'
$script:processRecords = New-Object System.Collections.ArrayList
$script:processByPid = @{}
$script:observedPids = New-Object 'System.Collections.Generic.HashSet[int]'
$script:fileEvents = New-Object System.Collections.ArrayList
$script:fileEventByKey = @{}
$script:registryEvents = New-Object System.Collections.ArrayList
$script:registryEventByKey = @{}
$script:networkEvents = New-Object System.Collections.ArrayList
$script:networkEventByKey = @{}
$script:riskSignals = [ordered]@{}
$script:telemetryHealth = [ordered]@{
  processes = $false
  files = $false
  registry = $false
  network = $false
}
$script:knownUserRegistryHives = New-Object 'System.Collections.Generic.HashSet[string]'
$script:truncated = [ordered]@{
  processes = $false
  file_events = $false
  registry_events = $false
  network_events = $false
  file_snapshot = $false
}

$registryTargets = @(
  @{ path = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'; label = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' },
  @{ path = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'; label = 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
  @{ path = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; label = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' },
  @{ path = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'; label = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' },
  @{ path = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'; label = 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
  @{ path = 'Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; label = 'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
  @{ path = 'Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; label = 'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' },
  @{ path = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; label = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' },
  @{
    path = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    label = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    value_names = @('Shell', 'Userinit', 'Taskman')
  }
)

function Get-ActiveRegistryTargets {
  $targets = New-Object System.Collections.ArrayList
  foreach ($target in $registryTargets) { [void]$targets.Add($target) }

  # The service account's HKCU is not the remotely signed-in user's hive. Add a
  # bounded set of mounted human-user hives without scanning system hives.
  $userHiveCount = 0
  try {
    foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | Sort-Object PSChildName)) {
      if ($userHiveCount -ge 8) { break }
      $sid = [string]$hive.PSChildName
      $isHumanSid = $sid -match '^S-1-5-21-(?:\d+-){3}\d+$' -or $sid -match '^S-1-12-1-(?:\d+-){3}\d+$'
      if (!$isHumanSid -or $sid.EndsWith('_Classes', [StringComparison]::OrdinalIgnoreCase)) { continue }
      foreach ($suffix in @(
        'Software\Microsoft\Windows\CurrentVersion\Run',
        'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
      )) {
        [void]$targets.Add(@{
          path = "Registry::HKEY_USERS\$sid\$suffix"
          label = "HKU\$sid\$suffix"
          user_sid = $sid
        })
      }
      $userHiveCount++
    }
  } catch {
    # Interactive telemetry remains useful if HKU enumeration is denied.
  }
  return @($targets.ToArray())
}

function Get-UtcTimestamp {
  return [DateTime]::UtcNow.ToString('o')
}

function Set-AnalysisPhase([string] $name) {
  $script:currentPhase = $name
  if (!$script:phaseTimestamps.Contains($name)) {
    $script:phaseTimestamps[$name] = Get-UtcTimestamp
  }
}

function Get-BoundedInteger([string] $rawValue, [int] $defaultValue, [int] $minimum, [int] $maximum) {
  $parsed = 0
  if (![int]::TryParse($rawValue, [ref]$parsed)) { return $defaultValue }
  if ($parsed -lt $minimum) { return $minimum }
  if ($parsed -gt $maximum) { return $maximum }
  return $parsed
}

function Get-SafeText([object] $value, [int] $maximumLength) {
  if ($null -eq $value) { return '' }
  $text = [string]$value
  $text = [regex]::Replace($text, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '?')
  $text = $text.Replace("`r", ' ').Replace("`n", ' ').Trim()
  if ($text.Length -gt $maximumLength) { return $text.Substring(0, $maximumLength) }
  return $text
}

function Get-RedactedCommandLine([object] $value) {
  $text = Get-SafeText $value 4096
  if ([string]::IsNullOrWhiteSpace($text)) { return '' }

  # Keep the command shape useful for process-tree investigation while removing
  # values commonly passed after secret-bearing switches or assignments.
  $keyedSecret = '(?i)(?<key>(?:--?|/)?(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|credential|credentials|api[_-]?key))(?<sep>\s*[:=]\s*|\s+)(?<value>"[^"]*"|''[^'']*''|\S+)'
  $text = [regex]::Replace($text, $keyedSecret, '${key}${sep}[REDACTED]')
  $text = [regex]::Replace($text, '(?i)\bBearer\s+\S+', 'Bearer [REDACTED]')
  $text = [regex]::Replace($text, '(?i)(https?://[^:/\s]+:)[^@\s]+@', '$1[REDACTED]@')
  $text = [regex]::Replace($text, '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?\b', '[REDACTED_JWT]')
  $text = [regex]::Replace($text, '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[REDACTED_AWS_KEY]')
  return Get-SafeText $text 1024
}

function Get-SafeExceptionCode([System.Exception] $exception) {
  if ($null -eq $exception) { return 'UnknownError' }
  # Exception messages can contain request URLs, file names, or other attacker-
  # controlled data. The type name is stable and safe for a remote report.
  return Get-SafeText ($exception.GetType().Name) 80
}

function Get-StringSha256([string] $value) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($value)
    return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Get-FileSha256([string] $path) {
  try {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  } catch {
    return $null
  }
}

function Add-RiskSignal([string] $id, [int] $weight, [string] $description) {
  if (!$script:riskSignals.Contains($id)) {
    $script:riskSignals[$id] = [ordered]@{
      id = $id
      weight = $weight
      description = Get-SafeText $description 180
      first_seen_utc = Get-UtcTimestamp
    }
  }
}

function Get-PhaseSummary {
  $parts = New-Object System.Collections.ArrayList
  foreach ($entry in $script:phaseTimestamps.GetEnumerator()) {
    [void]$parts.Add(("{0}@{1}" -f $entry.Key, $entry.Value))
  }
  return ($parts -join ',')
}

function Get-TruncationSummary {
  $names = New-Object System.Collections.ArrayList
  foreach ($entry in $script:truncated.GetEnumerator()) {
    if ([bool]$entry.Value) { [void]$names.Add([string]$entry.Key) }
  }
  if ($names.Count -eq 0) { return 'none' }
  return ($names -join ',')
}

function Reset-TelemetryHealth {
  foreach ($name in @($script:telemetryHealth.Keys)) {
    $script:telemetryHealth[$name] = $false
  }
}

function Get-DegradedTelemetrySummary {
  $names = New-Object System.Collections.ArrayList
  foreach ($entry in $script:telemetryHealth.GetEnumerator()) {
    if (![bool]$entry.Value) { [void]$names.Add([string]$entry.Key) }
  }
  if ($names.Count -eq 0) { return 'none' }
  return ($names -join ',')
}

function Get-RiskAssessment([bool] $executionObserved, [bool] $timedOut, [bool] $executionFailed) {
  $score = 0
  $signalIds = New-Object System.Collections.ArrayList
  foreach ($signal in $script:riskSignals.Values) {
    $score += [int]$signal.weight
    [void]$signalIds.Add([string]$signal.id)
  }
  if ($score -gt 100) { $score = 100 }

  $verdict = 'completed_no_obvious_behavior'
  if ($executionFailed) {
    $verdict = 'execution_failed'
  } elseif (!$executionObserved -and $analysisMode -eq 'interactive') {
    $verdict = 'interactive_no_execution_observed'
  } elseif ($score -ge 60) {
    $verdict = 'high_risk_behavior_observed'
  } elseif ($score -ge 20) {
    $verdict = 'suspicious_behavior_observed'
  } elseif ($timedOut) {
    $verdict = 'analysis_inconclusive_timed_out'
  } elseif ((Get-DegradedTelemetrySummary) -ne 'none') {
    # Never issue a clean-looking verdict when a required evidence channel was
    # unavailable for the whole observation window.
    $verdict = 'analysis_inconclusive_telemetry_degraded'
  }

  return [ordered]@{
    verdict = $verdict
    risk_score = $score
    signals = if ($signalIds.Count -eq 0) { 'none' } else { $signalIds -join ',' }
  }
}

function Limit-ReportArray([object[]] $values, [int] $limit) {
  # PowerShell enumerates function output by default: one item becomes an
  # object and zero items become $null. Preserve the outer array so JSON always
  # contains the lists required by the gateway contract.
  if ($null -eq $values) { return ,@() }
  if ($values.Count -le $limit) { return ,@($values) }
  return ,@($values[0..($limit - 1)])
}

function Submit-ReportBody([hashtable] $body, [bool] $throwOnFailure) {
  $json = $body | ConvertTo-Json -Depth 8 -Compress
  $lastException = $null
  # Two bounded final attempts (2 * 4s + one 1s backoff) fit inside the
  # backend's 15-second post-lease report/cleanup grace window.
  $attemptLimit = if ($throwOnFailure) { 2 } else { 1 }
  for ($attempt = 1; $attempt -le $attemptLimit; $attempt++) {
    try {
      Invoke-RestMethod -Method Post -Uri "$api/v1/sandbox-cloud/agent/sessions/$session/report" -Headers $headers -ContentType 'application/json' -Body $json -TimeoutSec 4 | Out-Null
      return $true
    } catch {
      $lastException = $_.Exception
      if ($attempt -lt $attemptLimit) { Start-Sleep -Seconds 1 }
    }
  }
  if ($throwOnFailure -and $null -ne $lastException) { throw $lastException }
  return $false
}

function Send-ProgressReport([string] $status, [string] $verdict, [string] $summary) {
  # Older gateways reject status=staged. This is intentionally best-effort so
  # an older deployment still reaches the final completed/failed report.
  $body = @{
    status = $status
    verdict = $verdict
    summary = Get-SafeText $summary 1900
    process_tree = @()
    file_events = Limit-ReportArray @($script:fileEvents.ToArray()) $maxFileEvents
    registry_events = @()
    network_events = @()
  }
  [void](Submit-ReportBody $body $false)
}

function Send-FinalReport([string] $status, [string] $verdict, [string] $summary) {
  $body = @{
    status = $status
    verdict = $verdict
    summary = Get-SafeText $summary 1900
    process_tree = Limit-ReportArray @($script:processRecords.ToArray()) $maxProcesses
    file_events = Limit-ReportArray @($script:fileEvents.ToArray()) $maxFileEvents
    registry_events = Limit-ReportArray @($script:registryEvents.ToArray()) $maxRegistryEvents
    network_events = Limit-ReportArray @($script:networkEvents.ToArray()) $maxNetworkEvents
  }
  [void](Submit-ReportBody $body $true)
}

function Initialize-MetadataIsolation {
  # EC2 user-data contains the short-lived bootstrap credential. Once this
  # SYSTEM agent has inherited it, neither the low-privilege sample nor a
  # remote investigation account may reach IMDS to read user-data or role data.
  $netshPath = Join-Path ([string]$env:SystemRoot) 'System32\netsh.exe'
  if (!(Test-Path -LiteralPath $netshPath -PathType Leaf)) {
    throw 'MetadataFirewallToolMissing'
  }
  $ruleName = 'Prewise Sandbox Block EC2 Metadata'
  & $netshPath advfirewall firewall delete rule "name=$ruleName" | Out-Null
  & $netshPath advfirewall firewall add rule "name=$ruleName" dir=out action=block protocol=any remoteip=169.254.169.254 profile=any enable=yes | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'MetadataFirewallRuleFailed' }
}

function Initialize-LocalAccountApi {
  # System.DirectoryServices/ADSI is not reliable during early EC2 user-data
  # startup (and raised ExtendedTypeSystemException on the production AMI).
  # Netapi32 is present on every supported Windows 7-11 image and does not
  # depend on the WinNT ADSI provider being initialized.
  if ($null -ne ('PrewiseSandboxNative.LocalAccounts' -as [type])) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PrewiseSandboxNative {
  public static class LocalAccounts {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_1 {
      [MarshalAs(UnmanagedType.LPWStr)] public string name;
      [MarshalAs(UnmanagedType.LPWStr)] public string password;
      public UInt32 passwordAge;
      public UInt32 privilege;
      [MarshalAs(UnmanagedType.LPWStr)] public string homeDirectory;
      [MarshalAs(UnmanagedType.LPWStr)] public string comment;
      public UInt32 flags;
      [MarshalAs(UnmanagedType.LPWStr)] public string scriptPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_MEMBERS_INFO_3 {
      [MarshalAs(UnmanagedType.LPWStr)] public string domainAndName;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern UInt32 NetUserAdd(
      string serverName,
      UInt32 level,
      ref USER_INFO_1 buffer,
      out UInt32 parameterError);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern UInt32 NetUserDel(string serverName, string userName);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern UInt32 NetLocalGroupAddMembers(
      string serverName,
      string groupName,
      UInt32 level,
      ref LOCALGROUP_MEMBERS_INFO_3 buffer,
      UInt32 totalEntries);

    public static UInt32 CreateStandardUser(string userName, string password) {
      USER_INFO_1 info = new USER_INFO_1();
      info.name = userName;
      info.password = password;
      info.privilege = 1; // USER_PRIV_USER: never create an administrator.
      info.flags = 0x00000001 | 0x00010000; // UF_SCRIPT | UF_DONT_EXPIRE_PASSWD
      UInt32 parameterError;
      return NetUserAdd(null, 1, ref info, out parameterError);
    }

    public static UInt32 AddToLocalGroup(string groupName, string accountName) {
      LOCALGROUP_MEMBERS_INFO_3 member = new LOCALGROUP_MEMBERS_INFO_3();
      member.domainAndName = accountName;
      return NetLocalGroupAddMembers(null, groupName, 3, ref member, 1);
    }

    public static UInt32 DeleteUser(string userName) {
      return NetUserDel(null, userName);
    }
  }
}
'@ -ErrorAction Stop
}

function Initialize-SamplePrincipal {
  if ($analysisMode -ne 'auto') { return }
  $computerName = [string]$env:COMPUTERNAME
  Initialize-LocalAccountApi

  # A single-use AMI normally has no previous account. Still remove a stale
  # account deterministically if an interrupted agent run left one behind.
  $deleteResult = [PrewiseSandboxNative.LocalAccounts]::DeleteUser($sampleAccountName)
  if ($deleteResult -ne 0 -and $deleteResult -ne 2221) {
    throw ("LocalUserDeleteFailed_{0}" -f $deleteResult)
  }

  $randomBytes = New-Object byte[] 24
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($randomBytes)
  } finally {
    $rng.Dispose()
  }
  $randomText = [Convert]::ToBase64String($randomBytes).Replace('+', 'A').Replace('/', 'B').TrimEnd('=')
  $plainPassword = "Pw1!$randomText"
  try {
    $createResult = [PrewiseSandboxNative.LocalAccounts]::CreateStandardUser($sampleAccountName, $plainPassword)
    if ($createResult -ne 0) {
      throw ("LocalUserCreateFailed_{0}" -f $createResult)
    }
    $usersGroupName = ([Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $qualifiedAccountName = "{0}\{1}" -f $computerName, $sampleAccountName
    $groupResult = [PrewiseSandboxNative.LocalAccounts]::AddToLocalGroup($usersGroupName, $qualifiedAccountName)
    if ($groupResult -ne 0 -and $groupResult -ne 1378) {
      throw ("LocalGroupMembershipFailed_{0}" -f $groupResult)
    }
    $script:sampleAccountSecurePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
  } finally {
    # The cleartext is required only for NetUserAdd. Do not keep it in script
    # scope, and clear the random source buffer before untrusted code starts.
    $plainPassword = $null
    $randomText = $null
    [Array]::Clear($randomBytes, 0, $randomBytes.Length)
  }

  $account = New-Object Security.Principal.NTAccount($computerName, $sampleAccountName)
  $sid = $account.Translate([Security.Principal.SecurityIdentifier])
  $script:sampleAccountSid = $sid.Value
  $acl = Get-Acl -LiteralPath $sampleDir
  $rule = New-Object Security.AccessControl.FileSystemAccessRule(
    $account,
    'Modify',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow'
  )
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $sampleDir -AclObject $acl
}

function Remove-SamplePrincipal {
  if ($null -ne $script:sampleAccountSecurePassword) {
    $script:sampleAccountSecurePassword.Dispose()
    $script:sampleAccountSecurePassword = $null
  }
  if (![string]::IsNullOrWhiteSpace([string]$script:sampleAccountSid)) {
    try {
      foreach ($profile in @(Get-WmiObject -Class Win32_UserProfile -Filter ("SID='{0}'" -f $script:sampleAccountSid) -ErrorAction SilentlyContinue)) {
        [void]$profile.Delete()
      }
    } catch { }
  }
  try {
    Initialize-LocalAccountApi
    [void][PrewiseSandboxNative.LocalAccounts]::DeleteUser($sampleAccountName)
  } catch { }
  $script:sampleAccountSid = $null
}

function Reset-WorkingDirectories {
  foreach ($path in @($sampleDir, $evidenceDir)) {
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
}

function Remove-WorkingDirectories {
  foreach ($path in @($sampleDir, $evidenceDir)) {
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Start-SandboxProcess([string] $filePath, [string] $arguments, [string] $workingDirectory) {
  # EC2 user-data runs while the temporary SYSTEM profile can be unloading.
  # ProcessStartInfo avoids the Start-Process profile race and lets us scrub the
  # short-lived agent credential from the untrusted child environment.
  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $filePath
  $startInfo.Arguments = $arguments
  $startInfo.WorkingDirectory = $workingDirectory
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  if ($null -eq $script:sampleAccountSecurePassword) {
    throw 'SamplePrincipalUnavailable'
  }
  $startInfo.UserName = $sampleAccountName
  $startInfo.Domain = [string]$env:COMPUTERNAME
  $startInfo.Password = $script:sampleAccountSecurePassword
  # Load the disposable standard user's HKCU hive so persistence attempts made
  # by the sample are both realistic and visible under HKEY_USERS telemetry.
  $startInfo.LoadUserProfile = $true

  foreach ($environmentName in @($startInfo.EnvironmentVariables.Keys)) {
    if ($environmentName -match '(?i)(PREWISE_SANDBOX_|AWS_ACCESS_KEY|AWS_SECRET|AWS_SESSION_TOKEN|TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)') {
      $startInfo.EnvironmentVariables.Remove([string]$environmentName)
    }
  }
  try {
    return [System.Diagnostics.Process]::Start($startInfo)
  } finally {
    # The account remains for process ownership/cleanup, but its random secret
    # is no longer needed after CreateProcessWithLogonW returns.
    if ($null -ne $script:sampleAccountSecurePassword) {
      $script:sampleAccountSecurePassword.Dispose()
      $script:sampleAccountSecurePassword = $null
    }
  }
}

function Get-CurrentProcessMap {
  $map = @{}
  $items = @()
  if ($null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
    try {
      $items = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
      if ($items.Count -gt 0) { $script:telemetryHealth.processes = $true }
    } catch {
      $items = @()
    }
  }
  if ($items.Count -eq 0) {
    try {
      # Windows 7 and early WMF images do not always include CIM cmdlets. The
      # classic WMI API exposes the same Win32_Process fields needed below.
      $items = @(Get-WmiObject -Class Win32_Process -ErrorAction Stop)
      if ($items.Count -gt 0) { $script:telemetryHealth.processes = $true }
    } catch {
      # A partial report is preferable when both process APIs are unavailable.
      $items = @()
    }
  }
  foreach ($item in $items) {
    $processId = [int]$item.ProcessId
    $map[[string]$processId] = $item
  }
  return $map
}

function Test-PathInsideSampleDirectory([string] $candidate) {
  if ([string]::IsNullOrWhiteSpace($candidate)) { return $false }
  try {
    $root = [IO.Path]::GetFullPath($sampleDir).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($candidate)
    return $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)
  } catch {
    return $false
  }
}

function Add-ObservedProcess([object] $item, [string] $source) {
  if ($null -eq $item) { return }
  $processId = [int]$item.ProcessId
  $key = [string]$processId
  $now = Get-UtcTimestamp

  if ($script:processByPid.ContainsKey($key)) {
    $record = $script:processByPid[$key]
    $record.last_seen_utc = $now
    $record.observed_running = $true
    return
  }
  if ($script:processRecords.Count -ge $maxProcesses) {
    $script:truncated.processes = $true
    return
  }

  $image = Get-SafeText $item.ExecutablePath 520
  if ([string]::IsNullOrWhiteSpace($image)) { $image = Get-SafeText $item.Name 260 }
  $rawCommandLine = Get-SafeText $item.CommandLine 4096
  $commandLine = Get-RedactedCommandLine $rawCommandLine
  $record = [ordered]@{
    record_type = 'process'
    pid = $processId
    parent_pid = [int]$item.ParentProcessId
    executable_path = $image
    command_line = $commandLine
    command_line_redacted = ($commandLine -ne $rawCommandLine)
    observation_source = $source
    first_seen_utc = $now
    last_seen_utc = $now
    phase = $script:currentPhase
    observed_running = $true
    exited = $false
    exit_code = $null
  }

  $leafName = [IO.Path]::GetFileName(([string]$item.Name)).ToLowerInvariant()
  if ($leafName -in @('mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'wscript.exe', 'cscript.exe')) {
    $record.evidence_id = 'SUSPICIOUS_SYSTEM_UTILITY'
    $record.severity = 'medium'
    Add-RiskSignal 'SUSPICIOUS_SYSTEM_UTILITY' 25 'Observed sample process tree using a frequently abused Windows utility.'
  }

  [void]$script:observedPids.Add($processId)
  $script:processByPid[$key] = $record
  [void]$script:processRecords.Add($record)
}

function Observe-ProcessGraph([hashtable] $currentMap, [int[]] $candidateRoots, [string] $source) {
  foreach ($rootId in @($candidateRoots)) {
    if ($rootId -gt 0) { [void]$script:observedPids.Add([int]$rootId) }
  }

  $changed = $true
  while ($changed) {
    $changed = $false
    foreach ($item in $currentMap.Values) {
      $processId = [int]$item.ProcessId
      $parentId = [int]$item.ParentProcessId
      if (!$script:observedPids.Contains($processId) -and $script:observedPids.Contains($parentId)) {
        [void]$script:observedPids.Add($processId)
        $changed = $true
      }
    }
  }

  foreach ($processId in @($script:observedPids)) {
    $key = [string]$processId
    if ($currentMap.ContainsKey($key)) {
      Add-ObservedProcess $currentMap[$key] $source
    } elseif ($script:processByPid.ContainsKey($key)) {
      $script:processByPid[$key].observed_running = $false
      $script:processByPid[$key].exited = $true
    }
  }
}

function Find-InteractiveRoots([hashtable] $currentMap, [hashtable] $baselinePids) {
  $roots = New-Object System.Collections.ArrayList
  foreach ($item in $currentMap.Values) {
    $key = [string][int]$item.ProcessId
    if ($baselinePids.ContainsKey($key) -or $script:observedPids.Contains([int]$item.ProcessId)) { continue }

    $image = [string]$item.ExecutablePath
    $commandLine = [string]$item.CommandLine
    $matchesStagedSample = Test-PathInsideSampleDirectory $image
    if (!$matchesStagedSample -and ![string]::IsNullOrWhiteSpace($commandLine)) {
      $matchesStagedSample = $commandLine.IndexOf($samplePath, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    if ($matchesStagedSample) { [void]$roots.Add([int]$item.ProcessId) }
  }
  return @($roots.ToArray())
}

function Stop-ObservedProcesses {
  $ids = @($script:observedPids) | Sort-Object -Descending
  foreach ($processId in $ids) {
    Stop-Process -Id ([int]$processId) -Force -ErrorAction SilentlyContinue
  }
}

function Get-FileSnapshot {
  $snapshot = @{}
  $root = [IO.Path]::GetFullPath($sampleDir).TrimEnd('\') + '\'
  $count = 0
  try {
    # Avoid the Get-ChildItem -File dynamic parameter so the collector also
    # works on the older PowerShell builds still found on Windows 7 images.
    foreach ($item in @(Get-ChildItem -LiteralPath $sampleDir -Recurse -Force -ErrorAction Stop | Where-Object { !$_.PSIsContainer } | Sort-Object FullName)) {
      if ($count -ge $maxSnapshotFiles) {
        $script:truncated.file_snapshot = $true
        break
      }
      $full = [IO.Path]::GetFullPath($item.FullName)
      if (!$full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { continue }
      $relative = $full.Substring($root.Length)
      $safeRelative = Get-SafeText $relative 520
      if ([string]::IsNullOrWhiteSpace($safeRelative)) { continue }
      $snapshot[$safeRelative.ToLowerInvariant()] = [ordered]@{
        relative_path = $safeRelative
        full_path = $full
        size_bytes = [long]$item.Length
        last_write_utc = $item.LastWriteTimeUtc.ToString('o')
      }
      $count++
    }
    $script:telemetryHealth.files = $true
  } catch {
    # Preserve all telemetry already collected.
  }
  return $snapshot
}

function Add-FileEvent([string] $action, [hashtable] $item, [string] $timestamp) {
  $eventKey = ("{0}|{1}" -f $action, $item.relative_path.ToLowerInvariant())
  if ($script:fileEventByKey.ContainsKey($eventKey)) {
    $existing = $script:fileEventByKey[$eventKey]
    $existing.last_seen_utc = $timestamp
    $existing.observation_count = [int]$existing.observation_count + 1
    $existing.size_bytes = [long]$item.size_bytes
    return
  }
  if ($script:fileEvents.Count -ge $maxFileEvents) {
    $script:truncated.file_events = $true
    return
  }

  $event = [ordered]@{
    event_type = 'file_change'
    action = $action
    relative_path = $item.relative_path
    size_bytes = [long]$item.size_bytes
    first_seen_utc = $timestamp
    last_seen_utc = $timestamp
    observation_count = 1
    phase = $script:currentPhase
    content_exported = $false
  }
  $extension = [IO.Path]::GetExtension([string]$item.relative_path).ToLowerInvariant()
  if ($action -ne 'deleted' -and $executableArtifactExtensions -contains $extension -and $item.relative_path -notlike 'sample.*') {
    $event.evidence_id = 'EXECUTABLE_ARTIFACT_CHANGED'
    $event.severity = 'medium'
    Add-RiskSignal 'EXECUTABLE_ARTIFACT_CHANGED' 25 'The sample created or modified another executable or script in the analysis directory.'
  }
  $script:fileEventByKey[$eventKey] = $event
  [void]$script:fileEvents.Add($event)
}

function Compare-FileSnapshots([hashtable] $before, [hashtable] $after) {
  $now = Get-UtcTimestamp
  foreach ($key in $after.Keys) {
    if (!$before.ContainsKey($key)) {
      Add-FileEvent 'created' $after[$key] $now
    } elseif ($before[$key].size_bytes -ne $after[$key].size_bytes -or
              $before[$key].last_write_utc -ne $after[$key].last_write_utc) {
      Add-FileEvent 'modified' $after[$key] $now
    }
  }
  foreach ($key in $before.Keys) {
    if (!$after.ContainsKey($key)) { Add-FileEvent 'deleted' $before[$key] $now }
  }
}

function Add-StagedSampleEvent {
  if ($script:fileEvents.Count -ge $maxFileEvents) { return }
  $event = [ordered]@{
    event_type = 'sample_staged'
    relative_path = [IO.Path]::GetFileName($samplePath)
    size_bytes = [long](Get-Item -LiteralPath $samplePath -ErrorAction Stop).Length
    sha256 = $sampleSha256
    timestamp_utc = Get-UtcTimestamp
    phase = $script:currentPhase
    content_exported = $false
  }
  [void]$script:fileEvents.Add($event)
}

function Finalize-FileHashes {
  $hashed = 0
  foreach ($event in $script:fileEvents) {
    if ($hashed -ge 20) { break }
    if ($event.event_type -ne 'file_change' -or $event.action -eq 'deleted' -or $event.Contains('sha256')) { continue }
    $candidate = Join-Path $sampleDir ([string]$event.relative_path)
    if (!(Test-PathInsideSampleDirectory $candidate) -or !(Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
    try {
      $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
      if ($item.Length -le 25MB) {
        $hash = Get-FileSha256 $candidate
        if ($null -ne $hash) { $event.sha256 = $hash }
        $hashed++
      }
    } catch {
      # Hashing is optional evidence and must never prevent the final report.
    }
  }
}

function Get-RegistrySnapshot {
  $snapshot = @{}
  $activeTargets = @(Get-ActiveRegistryTargets)
  $openedTarget = $false
  foreach ($target in $activeTargets) {
    try {
      if (!(Test-Path -LiteralPath $target.path)) { continue }
      $isNewUserHive = $false
      if ($target.ContainsKey('user_sid')) {
        $isNewUserHive = !$script:knownUserRegistryHives.Contains([string]$target.user_sid)
        # The Auto principal is created fresh for this one sample. Its first
        # mounted hive is not pre-existing user state: autoruns already present
        # on that first snapshot were necessarily written during this run.
        if ($analysisMode -eq 'auto' -and
            ![string]::IsNullOrWhiteSpace([string]$script:sampleAccountSid) -and
            [string]$target.user_sid -eq [string]$script:sampleAccountSid) {
          $isNewUserHive = $false
        }
      }
      $key = Get-Item -LiteralPath $target.path -ErrorAction Stop
      $openedTarget = $true
      $names = @($key.GetValueNames() | Sort-Object | Select-Object -First 100)
      if ($target.ContainsKey('value_names')) {
        $allowedValueNames = @($target.value_names)
        $names = @($names | Where-Object { $allowedValueNames -contains $_ })
      }
      foreach ($valueName in $names) {
        $rawValue = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = $key.GetValueKind($valueName).ToString()
        $serialized = if ($rawValue -is [array]) { @($rawValue) -join "`0" } else { [string]$rawValue }
        $displayName = if ([string]::IsNullOrEmpty([string]$valueName)) { '(Default)' } else { Get-SafeText $valueName 260 }
        $snapshotKey = ("{0}|{1}" -f $target.label, $displayName).ToLowerInvariant()
        $snapshot[$snapshotKey] = [ordered]@{
          key = $target.label
          value_name = $displayName
          value_kind = $kind
          value_sha256 = Get-StringSha256 $serialized
          value_length = $serialized.Length
          baseline_only = $isNewUserHive
        }
      }
    } catch {
      # Registry access can be restricted by the AMI policy; continue safely.
    }
  }
  foreach ($target in $activeTargets) {
    if ($target.ContainsKey('user_sid')) { [void]$script:knownUserRegistryHives.Add([string]$target.user_sid) }
  }
  if ($openedTarget) { $script:telemetryHealth.registry = $true }
  return $snapshot
}

function Add-RegistryEvent([string] $action, [hashtable] $item, [string] $timestamp) {
  $eventKey = ("{0}|{1}|{2}" -f $action, $item.key, $item.value_name).ToLowerInvariant()
  if ($script:registryEventByKey.ContainsKey($eventKey)) {
    $existing = $script:registryEventByKey[$eventKey]
    $existing.last_seen_utc = $timestamp
    $existing.observation_count = [int]$existing.observation_count + 1
    $existing.value_sha256 = $item.value_sha256
    return
  }
  if ($script:registryEvents.Count -ge $maxRegistryEvents) {
    $script:truncated.registry_events = $true
    return
  }
  $event = [ordered]@{
    event_type = 'registry_persistence_change'
    action = $action
    key = $item.key
    value_name = $item.value_name
    value_kind = $item.value_kind
    value_sha256 = $item.value_sha256
    value_length = [int]$item.value_length
    first_seen_utc = $timestamp
    last_seen_utc = $timestamp
    observation_count = 1
    phase = $script:currentPhase
    raw_value_exported = $false
    evidence_id = 'PERSISTENCE_REGISTRY_CHANGED'
    severity = 'high'
  }
  Add-RiskSignal 'PERSISTENCE_REGISTRY_CHANGED' 40 'A selected Windows autorun or logon persistence value changed during analysis.'
  $script:registryEventByKey[$eventKey] = $event
  [void]$script:registryEvents.Add($event)
}

function Compare-RegistrySnapshots([hashtable] $before, [hashtable] $after) {
  $now = Get-UtcTimestamp
  foreach ($key in $after.Keys) {
    if (!$before.ContainsKey($key)) {
      # A user hive can mount after the service baseline when the remote user
      # signs in. Existing autoruns become the baseline, not sample evidence.
      if (![bool]$after[$key].baseline_only) { Add-RegistryEvent 'created' $after[$key] $now }
    } elseif ($before[$key].value_sha256 -ne $after[$key].value_sha256) {
      Add-RegistryEvent 'modified' $after[$key] $now
    }
  }
  foreach ($key in $before.Keys) {
    if (!$after.ContainsKey($key)) { Add-RegistryEvent 'deleted' $before[$key] $now }
  }
}

function Test-IsExternalAddress([string] $address) {
  if ([string]::IsNullOrWhiteSpace($address) -or $address -in @('*', '0.0.0.0', '::', '::1', '127.0.0.1')) { return $false }
  $parsedAddress = $null
  if (![Net.IPAddress]::TryParse($address, [ref]$parsedAddress)) { return $false }
  if ([Net.IPAddress]::IsLoopback($parsedAddress) -or $parsedAddress.IsIPv6LinkLocal) { return $false }
  $bytes = $parsedAddress.GetAddressBytes()
  if ($parsedAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    if ($bytes[0] -eq 10 -or $bytes[0] -eq 127 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) { return $false }
    if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
  } elseif (($bytes[0] -band 0xFE) -eq 0xFC) {
    return $false
  }
  return $true
}

function Add-NetworkEvent([string] $protocol, [int] $processId, [string] $localAddress, [int] $localPort, [string] $remoteAddress, [int] $remotePort, [string] $state) {
  $eventKey = ("{0}|{1}|{2}:{3}|{4}:{5}|{6}" -f $protocol, $processId, $localAddress, $localPort, $remoteAddress, $remotePort, $state).ToLowerInvariant()
  $now = Get-UtcTimestamp
  if ($script:networkEventByKey.ContainsKey($eventKey)) {
    $existing = $script:networkEventByKey[$eventKey]
    $existing.last_seen_utc = $now
    $existing.observation_count = [int]$existing.observation_count + 1
    return
  }
  if ($script:networkEvents.Count -ge $maxNetworkEvents) {
    $script:truncated.network_events = $true
    return
  }
  $event = [ordered]@{
    event_type = if ($protocol -eq 'tcp') { 'network_connection' } else { 'network_endpoint' }
    protocol = $protocol
    pid = $processId
    local_address = Get-SafeText $localAddress 80
    local_port = $localPort
    remote_address = Get-SafeText $remoteAddress 80
    remote_port = $remotePort
    state = Get-SafeText $state 40
    first_seen_utc = $now
    last_seen_utc = $now
    observation_count = 1
    phase = $script:currentPhase
  }
  if ($remotePort -gt 0 -and $state -ne 'Listen' -and (Test-IsExternalAddress $remoteAddress)) {
    $event.evidence_id = 'EXTERNAL_NETWORK_CONNECTION'
    $event.severity = 'medium'
    Add-RiskSignal 'EXTERNAL_NETWORK_CONNECTION' 20 'An observed sample process connected to a public network address.'
  }
  $script:networkEventByKey[$eventKey] = $event
  [void]$script:networkEvents.Add($event)
}

function ConvertFrom-NetworkEndpoint([string] $endpoint) {
  $address = ''
  $port = 0
  $value = $endpoint.Trim()
  if ($value -match '^\[(.*)\]:(\d+|\*)$') {
    $address = $Matches[1]
    if ($Matches[2] -ne '*') { [void][int]::TryParse($Matches[2], [ref]$port) }
  } else {
    $separator = $value.LastIndexOf(':')
    if ($separator -gt 0) {
      $address = $value.Substring(0, $separator)
      $portText = $value.Substring($separator + 1)
      if ($portText -ne '*') { [void][int]::TryParse($portText, [ref]$port) }
    } else {
      $address = $value
    }
  }
  return [ordered]@{ address = $address; port = $port }
}

function Capture-NetworkTelemetry {
  if ($script:observedPids.Count -eq 0) { return }
  $capturedWithCmdlet = $false
  try {
    if ($null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
      foreach ($connection in @(Get-NetTCPConnection -ErrorAction Stop)) {
        $ownerId = [int]$connection.OwningProcess
        if (!$script:observedPids.Contains($ownerId)) { continue }
        Add-NetworkEvent 'tcp' $ownerId ([string]$connection.LocalAddress) ([int]$connection.LocalPort) ([string]$connection.RemoteAddress) ([int]$connection.RemotePort) ([string]$connection.State)
      }
      if ($null -ne (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
          $ownerId = [int]$endpoint.OwningProcess
          if ($script:observedPids.Contains($ownerId)) {
            Add-NetworkEvent 'udp' $ownerId ([string]$endpoint.LocalAddress) ([int]$endpoint.LocalPort) '' 0 'Bound'
          }
        }
      }
      $capturedWithCmdlet = $true
      $script:telemetryHealth.network = $true
    }
  } catch {
    # Network telemetry is best-effort. The report records everything already
    # observed and never substitutes unrelated agent/gateway connections.
  }

  # Windows 7 / older PowerShell images may not expose NetTCPIP cmdlets. The
  # inbox netstat executable provides a safe, dependency-free fallback.
  if (!$capturedWithCmdlet) {
    try {
      $netstatPath = Join-Path ([string]$env:SystemRoot) 'System32\netstat.exe'
      if (!(Test-Path -LiteralPath $netstatPath -PathType Leaf)) { return }
      foreach ($line in @(& $netstatPath -ano -n 2>$null)) {
        $columns = @(([string]$line).Trim() -split '\s+')
        if ($columns.Count -lt 4) { continue }
        $protocol = ([string]$columns[0]).ToLowerInvariant()
        if ($protocol -notin @('tcp', 'udp')) { continue }
        $ownerId = 0
        if (![int]::TryParse([string]$columns[$columns.Count - 1], [ref]$ownerId) -or !$script:observedPids.Contains($ownerId)) { continue }
        $local = ConvertFrom-NetworkEndpoint ([string]$columns[1])
        $remote = ConvertFrom-NetworkEndpoint ([string]$columns[2])
        $state = if ($protocol -eq 'tcp' -and $columns.Count -ge 5) { [string]$columns[3] } else { 'Bound' }
        Add-NetworkEvent $protocol $ownerId $local.address $local.port $remote.address $remote.port $state
      }
      if ($LASTEXITCODE -eq 0) { $script:telemetryHealth.network = $true }
    } catch {
      # Preserve the partial report when both telemetry paths are unavailable.
    }
  }
}

function Add-ScreenshotMetadata([string] $phaseName) {
  if ($script:fileEvents.Count -ge $maxFileEvents) { return }
  $event = [ordered]@{
    event_type = 'screenshot_metadata'
    phase = $phaseName
    timestamp_utc = Get-UtcTimestamp
    pixels_exported = $false
    capture_status = 'not_attempted_non_interactive_session'
  }
  if (![Environment]::UserInteractive) {
    [void]$script:fileEvents.Add($event)
    return
  }

  $screenshotPath = Join-Path $evidenceDir ("screen-{0}.png" -f ([Guid]::NewGuid().ToString('N')))
  $bitmap = $null
  $graphics = $null
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object -TypeName System.Drawing.Bitmap -ArgumentList @([int]$bounds.Width, [int]$bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $item = Get-Item -LiteralPath $screenshotPath -ErrorAction Stop
    $event.capture_status = 'captured_ephemeral'
    $event.width = $bounds.Width
    $event.height = $bounds.Height
    $event.size_bytes = [long]$item.Length
    $event.sha256 = Get-FileSha256 $screenshotPath
  } catch {
    $event.capture_status = 'capture_unavailable'
    $event.error_code = Get-SafeExceptionCode $_.Exception
  } finally {
    if ($null -ne $graphics) { $graphics.Dispose() }
    if ($null -ne $bitmap) { $bitmap.Dispose() }
    Remove-Item -LiteralPath $screenshotPath -Force -ErrorAction SilentlyContinue
  }
  [void]$script:fileEvents.Add($event)
}

function Invoke-TelemetryPoll([hashtable] $previousFiles, [hashtable] $previousRegistry, [int[]] $candidateRoots, [string] $source) {
  # Persisted artifacts can outlive a short sample process. Capture them first
  # so a slow CIM/WMI provider cannot consume the whole observation window.
  $currentFiles = Get-FileSnapshot
  Compare-FileSnapshots $previousFiles $currentFiles
  $currentRegistry = Get-RegistrySnapshot
  Compare-RegistrySnapshots $previousRegistry $currentRegistry

  $currentProcesses = Get-CurrentProcessMap
  Observe-ProcessGraph $currentProcesses $candidateRoots $source
  Capture-NetworkTelemetry

  return [ordered]@{
    processes = $currentProcesses
    files = $currentFiles
    registry = $currentRegistry
  }
}

function Invoke-AutoAnalysis([hashtable] $fileBaseline, [hashtable] $registryBaseline, [int] $executionTimeoutSeconds) {
  Set-AnalysisPhase 'auto_execution_started'
  Initialize-SamplePrincipal
  Add-ScreenshotMetadata 'before_auto_execution'
  $extension = [IO.Path]::GetExtension($samplePath).ToLowerInvariant()
  $launchFilePath = $samplePath
  $launchArguments = ''
  switch ($extension) {
    '.msi' { $launchFilePath = 'msiexec.exe'; $launchArguments = "/i `"$samplePath`" /qn /norestart"; break }
    { $_ -in @('.bat', '.cmd') } { $launchFilePath = 'cmd.exe'; $launchArguments = "/d /c `"$samplePath`""; break }
    '.ps1' { $launchFilePath = 'powershell.exe'; $launchArguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$samplePath`""; break }
  }
  $process = Start-SandboxProcess $launchFilePath $launchArguments $sampleDir
  if ($null -eq $process) { throw 'SandboxProcessStartFailed' }

  $rootId = [int]$process.Id
  # Seed authoritative launch evidence immediately. A short-lived or failed
  # root can disappear before the first (potentially slow) CIM/WMI snapshot.
  $launchCommandLine = if ([string]::IsNullOrWhiteSpace($launchArguments)) {
    "`"$launchFilePath`""
  } else {
    "`"$launchFilePath`" $launchArguments"
  }
  $rootProcessItem = New-Object psobject -Property @{
    ProcessId = $rootId
    ParentProcessId = [int]$PID
    ExecutablePath = $launchFilePath
    Name = [IO.Path]::GetFileName($launchFilePath)
    CommandLine = $launchCommandLine
  }
  Add-ObservedProcess $rootProcessItem 'auto-root-launch'
  # Baseline collection runs before untrusted execution. Reset here so a
  # successful baseline cannot hide a collector that failed throughout the
  # actual observation window.
  Reset-TelemetryHealth

  $deadline = [DateTime]::UtcNow.AddSeconds($executionTimeoutSeconds)
  $rootExitedAt = $null
  $files = $fileBaseline
  $registry = $registryBaseline

  while ([DateTime]::UtcNow -lt $deadline) {
    $poll = Invoke-TelemetryPoll $files $registry @($rootId) 'auto'
    $files = $poll.files
    $registry = $poll.registry

    if ($process.HasExited) {
      if ($null -eq $rootExitedAt) { $rootExitedAt = [DateTime]::UtcNow }
      if (([DateTime]::UtcNow - $rootExitedAt).TotalSeconds -ge 5) { break }
    }
    Start-Sleep -Milliseconds 1000
  }

  $timedOut = !$process.HasExited
  if ($timedOut) { Add-RiskSignal 'EXECUTION_TIMEOUT' 10 'The sample did not exit within the bounded automatic analysis window.' }
  $rootExitCode = if (!$timedOut -and $process.HasExited) { [int]$process.ExitCode } else { $null }
  $executionFailed = $null -ne $rootExitCode -and $rootExitCode -ne 0
  if ($executionFailed) {
    Add-RiskSignal 'SAMPLE_NONZERO_EXIT' 10 'The sample root process exited with a non-zero status.'
  }

  $finalProcesses = Get-CurrentProcessMap
  Observe-ProcessGraph $finalProcesses @($rootId) 'auto-final'
  $lingeringChildren = 0
  foreach ($processId in @($script:observedPids)) {
    if ($finalProcesses.ContainsKey([string]$processId) -and [int]$processId -ne $rootId) { $lingeringChildren++ }
  }
  if ($lingeringChildren -gt 0) {
    Add-RiskSignal 'LINGERING_CHILD_PROCESS' 15 'One or more child processes remained after the sample root process ended.'
  }

  Stop-ObservedProcesses
  if ($script:processByPid.ContainsKey([string]$rootId)) {
    $rootRecord = $script:processByPid[[string]$rootId]
    $rootRecord.exited = $process.HasExited
    $rootRecord.observed_running = !$process.HasExited
    $rootRecord.exit_code = $rootExitCode
  }

  Set-AnalysisPhase 'auto_execution_finished'
  Add-ScreenshotMetadata 'after_auto_execution'
  $filesFinal = Get-FileSnapshot
  Compare-FileSnapshots $files $filesFinal
  $registryFinal = Get-RegistrySnapshot
  Compare-RegistrySnapshots $registry $registryFinal

  return [ordered]@{
    execution_observed = $true
    timed_out = $timedOut
    execution_failed = $executionFailed
    root_exit_code = $rootExitCode
    lingering_children = $lingeringChildren
  }
}

function Invoke-InteractiveAnalysis([hashtable] $fileBaseline, [hashtable] $registryBaseline, [hashtable] $processBaseline, [DateTime] $leaseDeadlineUtc, [int] $leaseSecondsAtDelivery) {
  Set-AnalysisPhase 'interactive_sample_staged'
  Add-ScreenshotMetadata 'interactive_staged'
  $remainingBeforeProgress = [Math]::Max(0, [Math]::Floor(($leaseDeadlineUtc - [DateTime]::UtcNow).TotalSeconds))
  if ($remainingBeforeProgress -gt 10) {
    Send-ProgressReport 'staged' 'staged_for_interactive_analysis' ("mode=interactive; phase=staged; lease_seconds_at_delivery={0}; remaining_seconds={1}; sample_sha256={2}; phases={3}" -f $leaseSecondsAtDelivery, $remainingBeforeProgress, $sampleSha256, (Get-PhaseSummary))
  }

  Set-AnalysisPhase 'interactive_observation_started'
  # The lease deadline is anchored when the ready backend delivers the sample.
  # Baseline/progress time consumes the lease rather than extending it. The user
  # keeps the complete remaining control window; report/cleanup happens in the
  # backend's separate post-lease grace period.
  $finalizationMarginSeconds = 0
  $observationDeadlineUtc = $leaseDeadlineUtc
  $files = $fileBaseline
  $registry = $registryBaseline
  $executionObserved = $false

  while ([DateTime]::UtcNow -lt $observationDeadlineUtc) {
    $currentProcesses = Get-CurrentProcessMap
    $roots = Find-InteractiveRoots $currentProcesses $processBaseline
    if ($roots.Count -gt 0) {
      $executionObserved = $true
      Observe-ProcessGraph $currentProcesses $roots 'interactive'
    } elseif ($script:observedPids.Count -gt 0) {
      Observe-ProcessGraph $currentProcesses @() 'interactive'
    }
    Capture-NetworkTelemetry

    $currentFiles = Get-FileSnapshot
    Compare-FileSnapshots $files $currentFiles
    $files = $currentFiles
    $currentRegistry = Get-RegistrySnapshot
    Compare-RegistrySnapshots $registry $currentRegistry
    $registry = $currentRegistry
    Start-Sleep -Milliseconds 1000
  }

  Set-AnalysisPhase 'interactive_lease_elapsed'
  Stop-ObservedProcesses
  Add-ScreenshotMetadata 'interactive_lease_end'
  $filesFinal = Get-FileSnapshot
  Compare-FileSnapshots $files $filesFinal
  $registryFinal = Get-RegistrySnapshot
  Compare-RegistrySnapshots $registry $registryFinal

  return [ordered]@{
    execution_observed = $executionObserved
    timed_out = $false
    execution_failed = $false
    root_exit_code = $null
    lingering_children = 0
    lease_seconds_at_delivery = $leaseSecondsAtDelivery
    finalization_margin_seconds = $finalizationMarginSeconds
  }
}

Set-AnalysisPhase 'agent_started'
Reset-WorkingDirectories
$executionTimeoutSeconds = Get-BoundedInteger ([string]$env:PREWISE_SANDBOX_EXECUTION_TIMEOUT_SECONDS) 90 60 120
# A VM can become ready before the user finishes choosing/consenting to a file.
# Wait for the whole normal cloud lease instead of abandoning the session after
# two minutes. The backend remains authoritative and returns 410 at lease end.
$downloadTimeoutSeconds = Get-BoundedInteger ([string]$env:PREWISE_SANDBOX_DOWNLOAD_TIMEOUT_SECONDS) 900 30 1800
$executionResult = $null
$finalReportAttempted = $false

try {
  Initialize-MetadataIsolation
  Set-AnalysisPhase 'awaiting_sample'
  $downloadDeadline = [DateTime]::UtcNow.AddSeconds($downloadTimeoutSeconds)
  while ([DateTime]::UtcNow -lt $downloadDeadline) {
    try {
      $response = Invoke-WebRequest -Uri "$api/v1/sandbox-cloud/agent/sessions/$session/exe" -Headers $headers -OutFile $downloadPath -UseBasicParsing -PassThru
      $filename = [string]$response.Headers['X-Sandbox-Sample-Filename']
      $extension = [IO.Path]::GetExtension($filename).ToLowerInvariant()
      if ($allowedExtensions -notcontains $extension) { throw 'UnsupportedSampleExtension' }

      $modeHeader = ([string]$response.Headers['X-Sandbox-Mode']).Trim().ToLowerInvariant()
      if ($modeHeader -eq 'interactive') { $analysisMode = 'interactive' } else { $analysisMode = 'auto' }
      # This header is remaining time, not a new plan duration. Preserve any
      # positive value (for example 297) instead of rounding it up to 300.
      $interactiveLeaseSeconds = Get-BoundedInteger ([string]$response.Headers['X-Sandbox-Lease-Seconds']) 300 1 600
      if ($analysisMode -eq 'interactive') {
        $interactiveLeaseDeadlineUtc = [DateTime]::UtcNow.AddSeconds($interactiveLeaseSeconds)
      }

      $samplePath = Join-Path $sampleDir ("sample" + $extension)
      Move-Item -LiteralPath $downloadPath -Destination $samplePath -Force
      $sampleSha256 = Get-FileSha256 $samplePath
      if ([string]::IsNullOrWhiteSpace($sampleSha256)) { throw 'SampleHashFailed' }
      break
    } catch {
      Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
      if ([DateTime]::UtcNow -lt $downloadDeadline) { Start-Sleep -Seconds 2 }
    }
  }

  if ([string]::IsNullOrWhiteSpace($samplePath) -or !(Test-Path -LiteralPath $samplePath -PathType Leaf)) {
    throw 'SampleDownloadDeadlineExceeded'
  }

  Set-AnalysisPhase 'sample_downloaded'
  Add-StagedSampleEvent
  $fileBaseline = Get-FileSnapshot
  $registryBaseline = Get-RegistrySnapshot
  $processBaseline = Get-CurrentProcessMap
  Set-AnalysisPhase 'baseline_collected'

  if ($analysisMode -eq 'interactive') {
    if ($null -eq $interactiveLeaseDeadlineUtc) { throw 'InteractiveLeaseDeadlineMissing' }
    $executionResult = Invoke-InteractiveAnalysis $fileBaseline $registryBaseline $processBaseline $interactiveLeaseDeadlineUtc $interactiveLeaseSeconds
  } else {
    $executionResult = Invoke-AutoAnalysis $fileBaseline $registryBaseline $executionTimeoutSeconds
  }

  Set-AnalysisPhase 'telemetry_finalized'
  Finalize-FileHashes
  $assessment = Get-RiskAssessment ([bool]$executionResult.execution_observed) ([bool]$executionResult.timed_out) ([bool]$executionResult.execution_failed)
  Set-AnalysisPhase 'reporting'
  $leaseSummary = if ($analysisMode -eq 'interactive') { "lease_seconds_at_delivery=$($executionResult.lease_seconds_at_delivery); finalization_margin_seconds=$($executionResult.finalization_margin_seconds); " } else { '' }
  $summary = "mode=$analysisMode; ${leaseSummary}risk_score=$($assessment.risk_score); signals=$($assessment.signals); execution_observed=$($executionResult.execution_observed); timed_out=$($executionResult.timed_out); telemetry_degraded=$(Get-DegradedTelemetrySummary); process_count=$($script:processRecords.Count); file_event_count=$($script:fileEvents.Count); registry_event_count=$($script:registryEvents.Count); network_event_count=$($script:networkEvents.Count); truncated=$(Get-TruncationSummary); phases=$(Get-PhaseSummary)"
  $finalReportAttempted = $true
  Send-FinalReport 'completed' $assessment.verdict $summary
} catch {
  Set-AnalysisPhase 'failed'
  Stop-ObservedProcesses
  $errorCode = Get-SafeExceptionCode $_.Exception
  $summary = "mode=$analysisMode; error_code=$errorCode; process_count=$($script:processRecords.Count); file_event_count=$($script:fileEvents.Count); registry_event_count=$($script:registryEvents.Count); network_event_count=$($script:networkEvents.Count); truncated=$(Get-TruncationSummary); phases=$(Get-PhaseSummary)"
  if (!$finalReportAttempted) {
    try { Send-FinalReport 'failed' 'analysis_failed' $summary } catch { }
  }
} finally {
  Set-AnalysisPhase 'cleanup'
  Stop-ObservedProcesses
  Remove-SamplePrincipal
  Remove-WorkingDirectories
  $headers.Clear()
  $token = $null
}
