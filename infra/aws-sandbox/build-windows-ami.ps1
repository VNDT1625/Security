[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)][ValidatePattern('^i-[0-9a-f]+$')][string]$SourceInstanceId,
  [Parameter(Mandatory)][ValidateSet('auto', 'interactive')][string]$Mode,
  [string]$Region = 'ap-southeast-1',
  [string]$Profile = 'default',
  [string]$NamePrefix = 'prewise-sandbox-windows',
  [switch]$NoReboot
)

$ErrorActionPreference = 'Stop'
$instance = aws ec2 describe-instances --instance-ids $SourceInstanceId --region $Region --profile $Profile `
  --query 'Reservations[0].Instances[0]' --output json | ConvertFrom-Json
if (!$instance.InstanceId) { throw 'Source instance was not found.' }
$managed = $instance.Tags | Where-Object { $_.Key -eq 'ManagedBy' -and $_.Value -eq 'PrewiseSandbox' }
if (!$managed) { throw 'Refusing to image an instance without ManagedBy=PrewiseSandbox.' }
if ($instance.PlatformDetails -notmatch 'Windows') { throw 'Source instance is not Windows.' }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$imageName = "$NamePrefix-$Mode-$stamp"
if (!$PSCmdlet.ShouldProcess($SourceInstanceId, "create AMI $imageName")) { return }

$args = @(
  'ec2', 'create-image', '--instance-id', $SourceInstanceId,
  '--name', $imageName, '--description', "Prewise $Mode disposable worker $stamp",
  '--region', $Region, '--profile', $Profile,
  '--tag-specifications',
  "ResourceType=image,Tags=[{Key=ManagedBy,Value=PrewiseSandbox},{Key=PrewiseMode,Value=$Mode}]",
  "ResourceType=snapshot,Tags=[{Key=ManagedBy,Value=PrewiseSandbox},{Key=PrewiseMode,Value=$Mode}]",
  '--output', 'text', '--query', 'ImageId'
)
if ($NoReboot) { $args += '--no-reboot' }
$imageId = & aws @args
if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^ami-') { throw 'AMI creation request failed.' }
Write-Host "Waiting for $imageId to become available..."
aws ec2 wait image-available --image-ids $imageId --region $Region --profile $Profile
if ($LASTEXITCODE -ne 0) { throw 'AMI did not become available.' }
Write-Output $imageId
