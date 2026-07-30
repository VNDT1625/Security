[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)][string]$UserName,
  [string]$BootstrapPolicyName = 'PrewiseSandboxBootstrap',
  [string]$RuntimePolicyName = 'PrewiseSandboxRuntime',
  [string]$Region = 'ap-southeast-1',
  [string]$Profile = 'default'
)

$ErrorActionPreference = 'Stop'
$runtimePolicy = Join-Path $PSScriptRoot 'iam-policy.json'
$identity = aws sts get-caller-identity --profile $Profile --region $Region --output json | ConvertFrom-Json
if (!$identity.Account) { throw 'AWS identity could not be verified.' }
Write-Host "Target AWS account: $($identity.Account); IAM user: $UserName"

if (!$PSCmdlet.ShouldProcess($UserName, 'install runtime policy and remove bootstrap policy after preflight')) { return }
aws iam put-user-policy --user-name $UserName --policy-name $RuntimePolicyName `
  --policy-document "file://$runtimePolicy" --profile $Profile
if ($LASTEXITCODE -ne 0) { throw 'Failed to install runtime policy; bootstrap policy was retained.' }

python (Join-Path $PSScriptRoot 'preflight.py')
if ($LASTEXITCODE -ne 0) {
  throw 'Preflight failed; bootstrap policy was retained. Fix configuration and retry.'
}

aws iam delete-user-policy --user-name $UserName --policy-name $BootstrapPolicyName --profile $Profile
if ($LASTEXITCODE -ne 0) { throw 'Runtime is ready, but bootstrap policy removal failed.' }
Write-Host 'Runtime preflight passed and bootstrap policy was removed.'
