[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)][string]$VpcId,
  [Parameter(Mandatory)][string]$PublicSubnetId,
  [Parameter(Mandatory)][string]$BrokerDomain,
  [Parameter(Mandatory)][string]$LetsEncryptEmail,
  [string]$Region = 'ap-southeast-1',
  [string]$Profile = 'default',
  [string]$StackName = 'prewise-sandbox',
  [string]$BrokerAllowedCidr = '0.0.0.0/0'
)

$ErrorActionPreference = 'Stop'
$template = Join-Path $PSScriptRoot 'cloudformation.yaml'
$identity = aws sts get-caller-identity --profile $Profile --region $Region --output json | ConvertFrom-Json
if (!$identity.Account) { throw 'AWS identity could not be verified.' }
Write-Host "Target AWS account: $($identity.Account), region: $Region"
if (!$PSCmdlet.ShouldProcess("AWS account $($identity.Account)", "deploy CloudFormation stack $StackName")) { return }

aws cloudformation deploy `
  --template-file $template `
  --stack-name $StackName `
  --capabilities CAPABILITY_NAMED_IAM `
  --region $Region `
  --profile $Profile `
  --no-fail-on-empty-changeset `
  --parameter-overrides `
    "VpcId=$VpcId" `
    "PublicSubnetId=$PublicSubnetId" `
    "BrokerDomain=$BrokerDomain" `
    "LetsEncryptEmail=$LetsEncryptEmail" `
    "BrokerAllowedCidr=$BrokerAllowedCidr"
if ($LASTEXITCODE -ne 0) { throw "CloudFormation deploy failed with exit code $LASTEXITCODE" }
aws cloudformation describe-stacks --stack-name $StackName --region $Region --profile $Profile `
  --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' --output table
