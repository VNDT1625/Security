# Prewise Sandbox Agent v2

This PowerShell agent belongs **only** in a hardened, disposable Windows AMI. It
stages one user-consented Windows sample and sends a bounded evidence report to
the Prewise gateway. The VM must be terminated after every session and must
never be reused for another user.

## Analysis modes

The sample download response selects the mode with `X-Sandbox-Mode`:

- `auto` (default and backward-compatible): the agent executes the sample for
  `PREWISE_SANDBOX_EXECUTION_TIMEOUT_SECONDS`, clamped to 60-120 seconds.
- `interactive`: the agent **does not execute the sample**. It stages the file at
  `C:\Prewise\Sample` and observes a manual investigation for the **remaining**
  duration in `X-Sandbox-Lease-Seconds`, bounded to 1-600 seconds with 300 used
  only when the header is absent. The deadline is anchored when the ready
  backend delivers the sample, so a value such as 297 is never rounded up to
  300. Baseline/progress work consumes that time. The user keeps the complete
  remaining control window through the anchored deadline; only then does the
  agent stop observed processes, finalize local evidence, and submit within the
  backend's separate 15-second report/cleanup grace period. It sends a
  best-effort `staged` progress report before observation when enough lease time
  remains, then sends the final report.

An interactive-capable gateway must accept `status=staged` without closing the
sample report and must permit a later `completed` or `failed` report. Older
gateways can still use `auto`; they may reject the optional staged progress
report, which the agent handles without exposing credentials or stopping the
final collection.

## Bounded evidence

Agent v2 uses Windows/PowerShell facilities already available in the AMI and
does not require an external telemetry executable. It collects at most:

- 100 processes: PID, parent PID, executable path, bounded command line, first
  and last observation, source mode, and root exit information. Password/token/
  secret/credential/API-key arguments, bearer tokens, URL userinfo, and common
  standalone credential formats are redacted before serialization.
- 200 file events inside `C:\Prewise\Sample`: create/modify/delete metadata and
  SHA-256 for a bounded number of small surviving artifacts. File contents are
  never included.
- 200 changes to selected Run, RunOnce, policy Run, and Winlogon persistence
  values. Registry data is represented only by type, length, and SHA-256; raw
  registry values are never included. Interactive mode also observes a bounded
  set of mounted `HKEY_USERS\<human SID>` hives; system and `*_Classes` hives are
  excluded, and a newly mounted hive is baselined before changes are reported.
- 200 TCP/UDP records attributable only to observed sample PIDs.
- Optional screenshot **metadata** (dimensions, byte count, SHA-256). Screenshot
  pixels remain local and ephemeral, and capture is skipped for non-interactive
  service sessions.

Every evidence record includes phase/timestamp context. The final summary lists
phase timestamps, evidence counts, bounded risk-signal IDs, and any truncated
collections. A verdict is evidence-based and carefully scoped: timeout alone is
reported as inconclusive rather than proof of malware.

## Required AMI controls

- Use a single-use VM, encrypted temporary disk, and delete-on-termination.
- Terminate the VM after completion, failure, cancellation, or lease expiry.
- Auto mode creates a transient local non-administrator principal with a random
  in-memory password, launches the sample under that identity, and removes its
  account/profile during cleanup. Interactive AMIs must likewise expose only a
  dedicated non-administrator investigation account.
- The reference agent installs a fail-closed outbound block for IPv4 IMDS before
  staging a sample, while provisioning disables the IPv6 metadata endpoint and
  metadata tags. The AMI/VPC policy must additionally deny guest access to cloud
  credentials, the control plane, RFC1918 networks, and operator networks.
- Route permitted internet traffic through a monitored, rate-limited egress
  proxy. Block lateral-movement and abuse-prone protocols by default.
- Disable clipboard, drive, printer, microphone, and camera redirection for
  interactive sessions unless an explicit product policy allows them.
- Configure `SANDBOX_PUBLIC_BASE_URL` as an HTTPS gateway reachable from the VM.
- Ensure the bootstrap always schedules provider-side termination independently
  of the agent, so killing the agent cannot keep a VM alive.

The reference agent provides polling-based, best-effort telemetry. A production
AMI should additionally use Sysmon/ETW and a controlled network sensor to retain
very short-lived events and DNS detail. Those sensors complement this agent; the
agent remains responsible for staging, bounded execution/observation, evidence
normalization, fail-safe reporting, process cleanup, and removal of local
working artifacts.
