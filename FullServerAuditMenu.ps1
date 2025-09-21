<#
.SYNOPSIS
  Menu-driven server audit for Windows Server 2022.
  Choose sections to run: services, ports, users, logs, scheduled tasks, startup programs, recent temp files.
  Saves results to a timestamped Desktop folder.
#>

# --- Setup output folder on Desktop ---
$desktop = [Environment]::GetFolderPath('Desktop')
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outDir = Join-Path $desktop "FullServerAudit_$timestamp"
New-Item -Path $outDir -ItemType Directory -Force | Out-Null

$txtOut  = Join-Path $outDir "audit_readable.txt"

Function Write-Log { param($s) ; $s | Out-File -FilePath $txtOut -Append -Encoding utf8 ; Write-Host $s }

# --- Require admin privileges ---
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run this script as Administrator." -ForegroundColor Red
    Exit 1
}

# --- Functions for each audit section ---
function Audit-Services {
    Write-Log "`n=== Services ==="
    $services = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName
    $services | ForEach-Object { Write-Log ("{0} ({1}) - {2} - Path: {3}" -f $_.Name, $_.DisplayName, $_.State, $_.PathName) }
    Pause
}

function Audit-Ports {
    Write-Log "`n=== Listening TCP Ports ==="
    $listeners = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
    $listeners | ForEach-Object {
        try { $proc = Get-Process -Id $_.OwningProcess } catch {}
        Write-Log ("Port {0} on {1} - PID {2} ({3})" -f $_.LocalPort, $_.LocalAddress, $_.OwningProcess, ($proc.ProcessName -or "unknown"))
    }
    Pause
}

function Audit-Users {
    Write-Log "`n=== Local Users ==="
    $users = Get-LocalUser | Select Name, Enabled, LastLogon
    $users | ForEach-Object { Write-Log ("{0} - Enabled: {1} - LastLogon: {2}" -f $_.Name, $_.Enabled, $_.LastLogon) }

    Write-Log "`n=== Administrators Group Members ==="
    $admins = Get-LocalGroupMember -Group "Administrators" | Select Name, ObjectClass
    $admins | ForEach-Object { Write-Log ("{0} ({1})" -f $_.Name, $_.ObjectClass) }
    Pause
}

function Audit-Logs {
    Write-Log "`n=== Recent Successful Logins (4624) - last 50 ==="
    $logons = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 50 |
              Select-Object TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}
    $logons | ForEach-Object { Write-Log ("{0} - {1}" -f $_.TimeCreated, $_.User) }

    Write-Log "`n=== Recent Failed Logins (4625) - last 50 ==="
    $failures = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50 |
                Select-Object TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}, @{Name='Status';Expression={$_.Properties[0].Value}}
    $failures | ForEach-Object { Write-Log ("{0} - {1} - Status: {2}" -f $_.TimeCreated, $_.User, $_.Status) }
    Pause
}

function Audit-ScheduledTasks {
    Write-Log "`n=== Scheduled Tasks ==="
    $tasks = Get-ScheduledTask | Select TaskName, State, Author
    $tasks | ForEach-Object { Write-Log ("{0} - {1} - Author: {2}" -f $_.TaskName, $_.State, $_.Author) }
    Pause
}

function Audit-Startup {
    Write-Log "`n=== Startup Programs ==="
    $startup = Get-CimInstance Win32_StartupCommand | Select Name, Command, User
    $startup | ForEach-Object { Write-Log ("{0} - Command: {1} - User: {2}" -f $_.Name, $_.Command, $_.User) }
    Pause
}

function Audit-RecentFiles {
    Write-Log "`n=== Recent Files in Temp (last 7 days) ==="
    $tempFiles = Get-ChildItem "C:\Windows\Temp","$env:TEMP" -Recurse -ErrorAction SilentlyContinue | 
                 Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
                 Select-Object FullName, LastWriteTime
    $tempFiles | ForEach-Object { Write-Log ("{0} - {1}" -f $_.FullName, $_.LastWriteTime) }
    Pause
}

# --- Menu loop ---
do {
    Clear-Host
    Write-Host "==============================="
    Write-Host "      Full Server Audit Menu"
    Write-Host "==============================="
    Write-Host "1. Audit Services"
    Write-Host "2. Audit Listening Ports"
    Write-Host "3. Audit Users & Admins"
    Write-Host "4. Audit Security Logs (Recent Logins)"
    Write-Host "5. Audit Scheduled Tasks"
    Write-Host "6. Audit Startup Programs"
    Write-Host "7. Audit Recent Temp Files"
    Write-Host "8. Exit"
    Write-Host "==============================="
    $choice = Read-Host "Choose an option (1-8)"
    switch ($choice) {
        "1" { Audit-Services }
        "2" { Audit-Ports }
        "3" { Audit-Users }
        "4" { Audit-Logs }
        "5" { Audit-ScheduledTasks }
        "6" { Audit-Startup }
        "7" { Audit-RecentFiles }
        "8" { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid choice"; Pause }
    }
} until ($choice -eq "8")

Write-Host "`nAudit complete. All results saved to: $outDir"
Invoke-Item -Path $outDir
