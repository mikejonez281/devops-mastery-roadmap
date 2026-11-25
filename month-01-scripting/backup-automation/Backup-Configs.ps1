[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$SourceDir = ".\configs",

    [Parameter(Mandatory = $false)]
    [string]$BackupDir = ".\backups",

    [Parameter(Mandatory = $false)]
    [int]$RetentionDays = 7
)

$ErrorActionPreference = "Stop"

function Write-DevOpsLog {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO"  { Write-Host "[$timestamp] [INFO]  $Message" -ForegroundColor Cyan }
        "WARN"  { Write-Host "[$timestamp] [WARN]  $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
        "OK"    { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
    }
}

Write-DevOpsLog "Starting Configuration Backup and Directory Validation..."

if (-not (Test-Path -Path $SourceDir -PathType Container)) {
    Write-DevOpsLog "Source directory '$SourceDir' does not exist! Aborting." -Level "ERROR"
    exit 1
}

$files = Get-ChildItem -Path $SourceDir -File
if ($files.Count -eq 0) {
    Write-DevOpsLog "No configuration files found in '$SourceDir'. Nothing to back up." -Level "WARN"
    exit 0
}

Write-DevOpsLog "Validated source directory. Found $($files.Count) configuration file(s)."
Write-DevOpsLog "Computing SHA-256 checksums for change tracking..."

$manifest = @()
foreach ($file in $files) {
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
    $manifest += [PSCustomObject]@{
        FileName     = $file.Name
        SizeKB       = [math]::Round($file.Length / 1KB, 2)
        SHA256       = $hash
        LastModified = $file.LastWriteTime
    }
}
$manifest | Format-Table -AutoSize

if (-not (Test-Path -Path $BackupDir -PathType Container)) {
    Write-DevOpsLog "Creating backup target directory '$BackupDir'..."
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$archiveName = "config_backup_$timestamp.zip"
$archivePath = Join-Path -Path $BackupDir -ChildPath $archiveName

Write-DevOpsLog "Creating archive '$archiveName'..."
Compress-Archive -Path "$SourceDir\*" -DestinationPath $archivePath -CompressionLevel Optimal

if (Test-Path -Path $archivePath) {
    $archiveSize = [math]::Round((Get-Item $archivePath).Length / 1KB, 2)
    Write-DevOpsLog "Backup successfully created: $archivePath ($archiveSize KB)" -Level "OK"
} else {
    Write-DevOpsLog "Failed to create archive!" -Level "ERROR"
    exit 1
}

Write-DevOpsLog "Checking for backups older than $RetentionDays days in '$BackupDir'..."
$cutoffDate = (Get-Date).AddDays(-$RetentionDays)
$oldBackups = Get-ChildItem -Path $BackupDir -Filter "config_backup_*.zip" | Where-Object { $_.LastWriteTime -lt $cutoffDate }

if ($oldBackups) {
    foreach ($old in $oldBackups) {
        Write-DevOpsLog "Pruning expired backup: $($old.Name)" -Level "WARN"
        Remove-Item -Path $old.FullName -Force
    }
} else {
    Write-DevOpsLog "No expired backups to prune."
}

Write-DevOpsLog "Backup task completed successfully." -Level "OK"
