<#
.SYNOPSIS
  Quick Windows Server 2022 hardening script for beginner cyber defense competitions.
  Stops risky services, secures admin accounts, audits ports & startup programs, and saves logs.
#>

# --- Setup output folder ---
$desktop = [Environment]::GetFolderPath('Desktop')
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outDir = Join-Path $desktop "HardeningAudit_$timestamp"
New-Item -Path $outDir -ItemType Directory -Force | Out-Null

$txtOut = Join-Path $outDir "hardening_log.txt"

Function Write-Log { param($s) ; $s | Out-File -FilePath $txtOut -Append -Encoding utf8 ; Write-Host $s }

# --- Require admin privileges ---
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run this script as Administrator." -ForegroundColor Red
    Exit 1
}

Write-Log "=== Windows Server Hardening - $timestamp ==="

# --- 1. Stop/Disable RDP & WinRM (if not needed immediately) ---
Write-Log "`n--- Stopping & Disabling RDP and WinRM ---"
Try {
    Stop-Service -Name TermService -Force
    Set-Service -Name TermService -StartupType Disabled
    Write-Log "RDP (TermService) stopped & disabled."
} Catch { Write-Log "Failed to stop RDP: $_" }

Try {
    Stop-Service -Name WinRM -Force
    Set-Service -Name WinRM -StartupType Disabled
    Write-Log "WinRM stopped & disabled."
} Catch { Write-Log "Failed to stop WinRM: $_" }

# --- 2. Audit & Secure Admin Accounts ---
Write-Log "`n--- Auditing Admin Accounts ---"
$admins = Get-LocalGroupMember -Group "Administrators" | Select Name, ObjectClass
$admins | ForEach-Object { Write-Log ("Admin: {0} ({1})" -f $_.Name, $_.ObjectClass) }

# Example: Change known admin passwords
# Uncomment and set strong passwords if allowed by competition rules
# Set-LocalUser -Name "Administrator" -Password (Read-Host -AsSecureString "Enter new password for Administrator")

# Disable unknown or unused accounts (example)
$knownAdmins = @("Administrator","YourCompUser") # Add your legitimate usernames
$admins | ForEach-Object {
    if ($_."Name" -notin $knownAdmins) {
        Disable-LocalUser -Name $_.Name
        Write-Log "Disabled unknown admin account: $_.Name"
    }
}

# --- 3. Close unnecessary listening ports ---
Write-Log "`n--- Current Listening TCP Ports ---"
$listeners = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
$listeners | ForEach-Object {
    try { $proc = Get-Process -Id $_.OwningProcess } catch {}
    Write-Log ("Port {0} on {1} - PID {2} ({3})" -f $_.LocalPort, $_.LocalAddress, $_.OwningProcess, ($proc.ProcessName -or "unknown"))
}

# --- 4. Audit Scheduled Tasks & Startup Programs ---
Write-Log "`n--- Scheduled Tasks (non-Microsoft) ---"
$tasks = Get-ScheduledTask | Where-Object {$_.Author -notlike "*Microsoft*"} | Select TaskName, State, Author
$tasks | ForEach-Object { Write-Log ("{0} - {1} - Author: {2}" -f $_.TaskName, $_.State, $_.Author) }

Write-Log "`n--- Startup Programs ---"
$startup = Get-CimInstance Win32_StartupCommand | Select Name, Command, User
$startup | ForEach-Object { Write-Log ("{0} - Command: {1} - User: {2}" -f $_.Name, $_.Command, $_.User) }

# --- 5. Save Audit Summary ---
Write-Log "`nHardening complete. Logs and audit saved to: $outDir"
Invoke-Item -Path $outDir
