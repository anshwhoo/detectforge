# DetectForge Lab Setup Script
# Downloads configuration files from wazuh/wazuh-docker v4.14.6 and generates TLS certificates.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$BaseUrl = "https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.6/single-node"

$ConfigFiles = @(
    "config/certs.yml",
    "config/wazuh_indexer/wazuh.indexer.yml",
    "config/wazuh_indexer/internal_users.yml",
    "config/wazuh_dashboard/opensearch_dashboards.yml",
    "config/wazuh_dashboard/wazuh.yml",
    "config/wazuh_cluster/wazuh_manager.conf"
)

Write-Host "[1/3] Fetching configuration templates from official Wazuh repo..." -ForegroundColor Cyan
foreach ($file in $ConfigFiles) {
    $targetPath = Join-Path $ScriptDir $file
    $targetDir = Split-Path -Parent $targetPath
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    if (-not (Test-Path $targetPath)) {
        Write-Host "  Downloading $file..."
        Invoke-WebRequest -Uri "$BaseUrl/$file" -OutFile $targetPath -UseBasicParsing
    } else {
        Write-Host "  $file already exists, skipping."
    }
}

if (-not (Test-Path "generate-indexer-certs.yml")) {
    Write-Host "  Downloading generate-indexer-certs.yml..."
    Invoke-WebRequest -Uri "$BaseUrl/generate-indexer-certs.yml" -OutFile "generate-indexer-certs.yml" -UseBasicParsing
}

Write-Host "[2/3] Generating TLS certificates..." -ForegroundColor Cyan
docker compose -f generate-indexer-certs.yml run --rm generator

Write-Host "[3/3] Starting Wazuh stack via Docker Compose..." -ForegroundColor Cyan
docker compose up -d

Write-Host "`nLab setup completed!" -ForegroundColor Green
Write-Host "Dashboard: https://localhost (admin / SecretPassword)"
Write-Host "Indexer API: https://localhost:9200 (admin / SecretPassword)"
Write-Host "Wazuh API: https://localhost:55000 (wazuh-wui / MyS3cr37P450r.*-)"
