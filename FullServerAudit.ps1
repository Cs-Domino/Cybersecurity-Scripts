<#
.SYNOPSIS
  Beginner-friendly full server audit script for Windows Server 2022.
  Collects services, users, ports, logs, scheduled tasks, startup items, and recent files.
  Saves results to a Desktop folder.
#>

# --- Setup output folder on Desktop ---
$desktop = [Environment]::GetFolderPath('Desktop')
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outDir = Join-Path $desktop "FullServerAudit_$timestamp"
New-Item -Path $outDir -ItemType Directory -Force | Out-Null

$txtOut  = Join-Path $outDir "audit_readable.txt"
$jsonOut = Join-Path $outDir "audit_structured.json"

Function Write-Log { param($s) ; $s | Out-File -FilePath $txtOut -Append -Encoding utf8 ; Write-Host $s }

# --- Require admin privileges ---
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuilt]()
