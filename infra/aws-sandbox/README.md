# Prewise AWS Sandbox deployment gate

This directory contains the operator-side pieces required before the product may
advertise Auto Analyze or Interactive Control as available. The application is
fail-closed: missing infrastructure must disable the mode before a credit is
reserved.

## What is automated here

- `cloudformation.yaml`: one HTTPS Guacamole host, Elastic IP, an Auto worker
  security group with no ingress, and an Interactive worker security group whose
  only inbound rule is TCP 3389 from the broker security group. The broker has
  no SSH ingress and is managed through SSM.
- `deploy.ps1`: confirmed CloudFormation deployment. It prints the target AWS
  account before changing anything. The database password is generated inside
  Secrets Manager and is never passed on the command line.
- `build-windows-ami.ps1`: images an already hardened, tagged Windows builder
  into a distinct `auto` or `interactive` AMI.
- `preflight.py`: validates the AMI, VPC boundary, broker health contract and a
  non-billable `RunInstances` DryRun.
- `transition-to-runtime.ps1`: installs the runtime policy, runs preflight, and
  removes the temporary bootstrap policy only after every check passes.
- `cleanup.py`: lists stale tagged session workers; deletion is opt-in and also
  requires the exact AWS account id.

The CloudFormation baseline deliberately returns HTTP 503 from `/health` and
does not publish Guacamole until the authenticated Prewise broker adapter has
been installed. This prevents a plain Guacamole login (and its default account)
from being mistaken for Interactive Control. A ready adapter must atomically
consume the backend one-time token, create/register a per-lease RDP credential,
disable clipboard/drive/printer/audio redirection, and make `/health` return the
contract below. Infrastructure alone is therefore not evidence that
Interactive is ready.

```json
{
  "status": "ok",
  "ready": true,
  "protocolVersion": "1",
  "capabilities": [
    "lease_enforcement",
    "one_time_token_consume",
    "remote_desktop"
  ]
}
```

## 1. IAM and account migration

Attach `iam-policy.json` to the backend workload role (preferred) or the
dedicated `prewise-sandbox` IAM user. Restrict the image, subnet and security
group ARNs to the deployment account after the first successful preflight.

Initial infrastructure creation needs additional authority. An AWS
administrator or a dedicated CloudFormation service role should deploy the
stack. `bootstrap-policy.json` is intentionally limited to manual EC2 network,
Elastic IP and AMI preparation; it is not an administrator policy and cannot
create the IAM roles in the stack. Never attach administrator access to the
runtime worker identity merely to make deployment pass.

The runtime backend must retain only `iam-policy.json`. After new-account E2E
passes, use `transition-to-runtime.ps1`; it refuses to remove bootstrap rights
when preflight fails. Keep the old account serving traffic until both new Auto
and Interactive E2E have passed, then switch configuration atomically.

Every worker launched by the backend carries `ManagedBy=PrewiseSandbox` and a
`PrewiseSession` tag. Termination permission is limited to instances carrying
that management tag.

## 2. Auto Analyze

Set the Auto AMI, private subnet, Auto security group and public HTTPS callback.
The AMI must contain the controls in `server/sandbox-agent/README.md`. The
security group has no inbound rule. Egress is only through the controlled NAT or
proxy needed to reach the callback.

Run the non-mutating preflight before enabling the mode:

```powershell
python infra/aws-sandbox/preflight.py
```

For Interactive, also set the broker SG only in the operator shell (it is a
preflight input, not an application secret):

```powershell
$env:AWS_SANDBOX_BROKER_SECURITY_GROUP_ID = 'sg-...'
python infra/aws-sandbox/preflight.py
```

`RunInstances` is checked with AWS DryRun and never creates a billable instance.

## 3. Interactive Control

Interactive needs a separate hardened AMI and security group. TCP 3389 must
never be public; only the private remote-desktop broker security group may reach
it. The broker must expose a stable HTTPS health endpoint implementing the
contract already validated by `CloudSandboxService`.

The Windows AMI must have the sandbox agent installed and start it from EC2
user-data using the per-session values supplied by the backend. Do not attach an
instance profile to a VM that executes untrusted samples. For Interactive, bake
a disabled non-administrator investigation account into the AMI and let the
trusted broker adapter activate it with a random per-lease secret over a private
channel; deactivate it at lease end. Never bake a reusable RDP password into an
AMI.

Example infrastructure deployment (the first run creates billable resources):

```powershell
.\infra\aws-sandbox\deploy.ps1 `
  -VpcId vpc-... -PublicSubnetId subnet-... `
  -BrokerDomain sandbox.example.com -LetsEncryptEmail ops@example.com -WhatIf
# Remove -WhatIf only after reviewing account, region, DNS and estimated cost.
```

Build the two AMIs from independently hardened and Sysprep-prepared builders:

```powershell
.\infra\aws-sandbox\build-windows-ami.ps1 -SourceInstanceId i-... -Mode auto -WhatIf
.\infra\aws-sandbox\build-windows-ami.ps1 -SourceInstanceId i-... -Mode interactive -WhatIf
```

Required production settings are listed in `.env.production.example`. Do not
turn on Interactive by copying the Auto security group if that group allows
uncontrolled access.

## 4. Release check

A paid release is ready only when all of these are true:

- preflight reports `AUTO=READY` and, when enabled, `INTERACTIVE=READY`;
- the SePay webhook is authenticated and an idempotent webhook test passes;
- a failed provision refunds the reserved credit;
- a completed/expired session terminates every EC2 instance with the session tag;
- the browser receives only a one-time broker token, never Windows credentials.

## 5. Cleanup and rollback

Preview stale disposable workers first:

```powershell
python infra/aws-sandbox/cleanup.py --profile prewise-new --older-than-minutes 30
```

Termination needs two explicit gates:

```powershell
python infra/aws-sandbox/cleanup.py --profile prewise-new `
  --older-than-minutes 30 --execute --confirm-account 123456789012
```

Deleting the CloudFormation stack removes the long-lived broker/network
resources but is not part of `cleanup.py`. Preserve stack outputs and the old
account configuration until rollback is no longer required.
