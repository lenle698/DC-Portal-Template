param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[a-z][a-z0-9_-]{1,62}$')]
  [string]$WarehouseId,

  [Parameter(Mandatory = $true)]
  [string]$TargetProject,

  [string]$CentralProject = $TargetProject,

  [ValidateSet('asia-southeast1')]
  [string]$Location = 'asia-southeast1',

  [string]$GcloudPath,
  [string]$BqPath
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $MyInvocation.MyCommand.Path

# Resolve gcloud and bq executables
if (-not $GcloudPath) {
  $gcloudCmd = Get-Command 'gcloud' -ErrorAction SilentlyContinue
  if ($gcloudCmd) {
    $GcloudPath = $gcloudCmd.Source
  } else {
    $defaultGcloud = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
    if (Test-Path $defaultGcloud) { $GcloudPath = $defaultGcloud } else { $GcloudPath = 'gcloud' }
  }
}

if (-not $BqPath) {
  $bqCmd = Get-Command 'bq' -ErrorAction SilentlyContinue
  if ($bqCmd) {
    $BqPath = $bqCmd.Source
  } else {
    $defaultBq = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\bq.cmd'
    if (Test-Path $defaultBq) { $BqPath = $defaultBq } else { $BqPath = 'bq' }
  }
}

$serviceAccounts = @{
  ingest = "dwh-ingest@$CentralProject.iam.gserviceaccount.com"
  transform = "dwh-transform@$CentralProject.iam.gserviceaccount.com"
  portal = "dwh-portal-read@$CentralProject.iam.gserviceaccount.com"
}

function Add-DatasetAccess {
  param([string]$DatasetId, [string]$Role, [string]$ServiceAccount)
  $token = (& $GcloudPath auth print-access-token).Trim()
  $headers = @{ Authorization = "Bearer $token" }
  $uri = "https://bigquery.googleapis.com/bigquery/v2/projects/$TargetProject/datasets/$DatasetId"
  try {
    $dataset = Invoke-RestMethod -Uri $uri -Headers $headers
    $access = @($dataset.access)
    $exists = $access | Where-Object { $_.role -eq $Role -and $_.userByEmail -eq $ServiceAccount }
    if (-not $exists) {
      $access += [PSCustomObject]@{ role = $Role; userByEmail = $ServiceAccount }
      $body = @{ access = $access } | ConvertTo-Json -Depth 10 -Compress
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType 'application/json' -Body $body | Out-Null
    }
  } catch {
    Write-Warning "Failed to grant $Role on $DatasetId to $ServiceAccount. Ensure caller has BigQuery Admin permissions."
  }
}

foreach ($dataset in @('dwh_raw', 'dwh_clean', 'dwh_mart', 'dwh_audit', 'dwh_secure')) {
  & $BqPath --project_id=$TargetProject --location=$Location show --dataset $dataset 2>$null
  if ($LASTEXITCODE -ne 0) {
    & $BqPath --project_id=$TargetProject --location=$Location mk --dataset $dataset
  }
}

& $GcloudPath projects add-iam-policy-binding $TargetProject --member="serviceAccount:$($serviceAccounts.ingest)" --role='roles/bigquery.jobUser' --condition=None --quiet 2>$null | Out-Null
& $GcloudPath projects add-iam-policy-binding $TargetProject --member="serviceAccount:$($serviceAccounts.transform)" --role='roles/bigquery.jobUser' --condition=None --quiet 2>$null | Out-Null
& $GcloudPath projects add-iam-policy-binding $TargetProject --member="serviceAccount:$($serviceAccounts.portal)" --role='roles/bigquery.jobUser' --condition=None --quiet 2>$null | Out-Null

Add-DatasetAccess -DatasetId 'dwh_raw' -Role 'WRITER' -ServiceAccount $serviceAccounts.ingest
Add-DatasetAccess -DatasetId 'dwh_raw' -Role 'READER' -ServiceAccount $serviceAccounts.transform
Add-DatasetAccess -DatasetId 'dwh_audit' -Role 'WRITER' -ServiceAccount $serviceAccounts.ingest
Add-DatasetAccess -DatasetId 'dwh_audit' -Role 'WRITER' -ServiceAccount $serviceAccounts.transform
Add-DatasetAccess -DatasetId 'dwh_clean' -Role 'WRITER' -ServiceAccount $serviceAccounts.transform
Add-DatasetAccess -DatasetId 'dwh_mart' -Role 'WRITER' -ServiceAccount $serviceAccounts.transform
Add-DatasetAccess -DatasetId 'dwh_mart' -Role 'READER' -ServiceAccount $serviceAccounts.portal
Add-DatasetAccess -DatasetId 'dwh_secure' -Role 'WRITER' -ServiceAccount $serviceAccounts.transform

$template = Get-Content -LiteralPath (Join-Path $workspace 'warehouse_bootstrap.sql') -Raw
$targetSql = $template.Replace('PROJECT_ID', $TargetProject).Replace('van-len', $TargetProject).Replace("'core' AS warehouse_id", "'$WarehouseId' AS warehouse_id")
$tempSql = Join-Path $env:TEMP ("warehouse-$WarehouseId.sql")
try {
  [System.IO.File]::WriteAllText($tempSql, $targetSql, [System.Text.UTF8Encoding]::new($false))
  & cmd.exe /c ('"' + $BqPath + '" --project_id=' + $TargetProject + ' --location=' + $Location + ' query --use_legacy_sql=false --format=none < "' + $tempSql + '"')
  if ($LASTEXITCODE -ne 0) { throw 'BigQuery schema deployment failed.' }
} finally {
  if (Test-Path -LiteralPath $tempSql) { Remove-Item -LiteralPath $tempSql -Force }
}

Write-Host "Warehouse '$WarehouseId' has been provisioned in project '$TargetProject'."
