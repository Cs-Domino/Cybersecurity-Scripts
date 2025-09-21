<#
.SYNOPSIS
  Collect forensic evidence for a suspected credential stealer DLL loaded into LSASS.

.DESCRIPTION
  - Gathers process info, network connections, module list (if possible), tasklist /m results,
    hashes and a quarantined copy of the DLL, scheduled tasks, services, autoruns, event logs,
    and saves everything to a timestamped folder.
  - Does NOT kill processes or change system state.
  - Optionally performs an LSASS memory dump if -AllowDump is specified and ProcDump is provided.

.PARAMETER DllPath
  Full path to the suspicious DLL (required).

.PARAMETER LsassPid
  PID of the lsass.exe process (required).

.PARAMETER AllowDump
  Switch to allow LSASS dump (default: $false). If true, ProcDumpPath must point to procdump.exe.

.PARAMETER ProcDumpPath
  Full path to procdump.exe (required if -AllowDump is used).

.EXAMPLE
  .\Collect-CredStealerEvidence.ps1 -DllPath "C:\Tools\Indigo\credStealer.dll" -LsassPid 624
#>

param(
  [Parameter(Mandatory=$true)] [string]$DllPath,
  [Parameter(Mandatory=$true)] [int]$LsassPid,
  [switch]$AllowDump = $false,
  [string]$ProcDumpPath = ""
)

function AbortIfNotElevated {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
  }
}

AbortIfNotElevated

# Prepare output folder
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$out = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\CredStealer_Evidence_$ts"
New-Item -Path $out -ItemType Directory -Force | Out-Null

Function Save-ObjectToFile($obj, $name) {
  $path = Join-Path $out $name
  try {
    if ($obj -is [System.Array] -or $obj -is [System.Collections.IEnumerable]) {
      $obj | Out-File -FilePath $path -Encoding utf8
    } else {
      $obj | Out-File -FilePath $path -Encoding utf8
    }
  } catch {
    "$_" | Out-File -FilePath $path -Encoding utf8
  }
}

Write-Output "Evidence directory: $out"

# 1) Basic file info & ACLs
if (-not (Test-Path $DllPath)) {
  Write-Error "DLL not found at path: $DllPath"
  exit 1
}
$dllItem = Get-Item -Path $DllPath -Force
Save-ObjectToFile -obj @("=== DLL File Info ===", $dllItem | Select FullName, Length, CreationTime, LastWriteTime | Format-List | Out-String) -name "dll_info.txt"

try {
  $acl = Get-Acl -Path $DllPath
  Save-ObjectToFile -obj ("=== DLL ACL ===", $acl | Format-List | Out-String) -name "dll_acl.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to get ACL: $_") -name "dll_acl.txt"
}

# 2) Compute hash and quarantine copy
try {
  $hash = Get-FileHash -Path $DllPath -Algorithm SHA256
  Save-ObjectToFile -obj ("SHA256: " + $hash.Hash) -name "dll_hash.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to hash file: $_") -name "dll_hash.txt"
}

# Quarantine directory (copy only, do not delete original)
$quarantine = Join-Path $out "Quarantine"
New-Item -Path $quarantine -ItemType Directory -Force | Out-Null
try {
  Copy-Item -Path $DllPath -Destination $quarantine -Force
  # make read-only to avoid accidental modification
  (Join-Path $quarantine (Split-Path $DllPath -Leaf)) | ForEach-Object { Set-ItemProperty -Path $_ -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue }
  Save-ObjectToFile -obj "Copied DLL to quarantine folder." -name "quarantine_info.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to copy DLL to quarantine: $_") -name "quarantine_info.txt"
}

# 3) tasklist /m for the module (fallback)
try {
  $tasklistOut = & cmd.exe /c "tasklist /m `"$([IO.Path]::GetFileName($DllPath))`"" 2>&1
  Save-ObjectToFile -obj ("=== tasklist /m output ===", $tasklistOut) -name "tasklist_m.txt"
} catch {
  Save-ObjectToFile -obj ("tasklist /m failed: $_") -name "tasklist_m.txt"
}

# 4) Processes referencing the path or DLL in commandline
try {
  $procsReferenced = Get-CimInstance Win32_Process | Where-Object {
    ($_.ExecutablePath -and $_.ExecutablePath -like "*Indigo*") -or
    ($_.CommandLine -and $_.CommandLine -like "*Indigo*") -or
    ($_.CommandLine -and $_.CommandLine -like "*$([IO.Path]::GetFileName($DllPath))*")
  } | Select ProcessId, Name, ExecutablePath, CommandLine
  Save-ObjectToFile -obj ("=== Processes referencing Indigo or DLL in commandline ===", $procsReferenced) -name "processes_referencing_dll.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to enumerate processes referencing path: $_") -name "processes_referencing_dll.txt"
}

# 5) Get info on LSASS pid (do not kill)
try {
  $lsass = Get-Process -Id $LsassPid -ErrorAction Stop
  Save-ObjectToFile -obj ("=== LSASS Process Info ===", $lsass | Select Id, Name, Path, StartTime | Format-List | Out-String) -name "lsass_info.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to get LSASS process info for PID $LsassPid: $_") -name "lsass_info.txt"
}

# 6) Try to list modules for LSASS (may fail / be incomplete)
try {
  $modules = (Get-Process -Id $LsassPid -ErrorAction Stop).Modules | Select ModuleName, FileName
  Save-ObjectToFile -obj ("=== LSASS Modules (may be incomplete) ===", $modules) -name "lsass_modules.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to enumerate LSASS modules (likely protected): $_") -name "lsass_modules.txt"
}

# 7) Network connections for LSASS PID
try {
  $netcons = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $LsassPid } | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
  Save-ObjectToFile -obj ("=== Network connections for PID $LsassPid ===", $netcons) -name "lsass_network_connections.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to get net connections for PID $LsassPid: $_") -name "lsass_network_connections.txt"
}

# 8) Services referencing Indigo/DLL path
try {
  $svcs = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*Indigo*" -or $_.PathName -like "*$([IO.Path]::GetFileName($DllPath))*" } | Select Name, DisplayName, PathName, StartMode, State
  Save-ObjectToFile -obj ("=== Services referencing Indigo/DLL ===", $svcs) -name "services_referencing_dll.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to enumerate services referencing path: $_") -name "services_referencing_dll.txt"
}

# 9) Scheduled tasks referencing Indigo/DLL
try {
  $tasks = Get-ScheduledTask | Where-Object {
    ($_.Actions -match 'Indigo') -or ($_.Actions -match [Regex]::Escape($([IO.Path]::GetFileName($DllPath))))
  } | Select TaskName, TaskPath, Author, State
  Save-ObjectToFile -obj ("=== Scheduled tasks referencing Indigo/DLL ===", $tasks) -name "scheduledtasks_referencing_dll.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to enumerate scheduled tasks: $_") -name "scheduledtasks_referencing_dll.txt"
}

# 10) Registry Run keys / Autoruns referencing Indigo/DLL
try {
  $runHKLM = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue) | Out-String
  $runHKCU = (Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue) | Out-String
  Save-ObjectToFile -obj ("=== HKLM Run ===", $runHKLM) -name "run_hklm.txt"
  Save-ObjectToFile -obj ("=== HKCU Run ===", $runHKCU) -name "run_hkcu.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to read Run keys: $_") -name "run_keys.txt"
}

# 11) Startup programs and Winlogon keys
try {
  $startup = Get-CimInstance Win32_StartupCommand | Select Name, Command, User
  Save-ObjectToFile -obj ("=== Startup Programs ===", $startup) -name "startup_programs.txt"
  $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select Shell, Userinit
  Save-ObjectToFile -obj ("=== Winlogon Keys ===", $winlogon | Format-List | Out-String) -name "winlogon_keys.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to enumerate startup/winlogon: $_") -name "startup_winlogon.txt"
}

# 12) Dump process list & tasks/services for context
try {
  Get-Process | Select Id,Name,Path,StartTime | Sort-Object Name | Export-Csv -Path (Join-Path $out "process_list.csv") -NoTypeInformation -Force
  Get-ScheduledTask | Select TaskName, TaskPath, Author, State | Export-Csv -Path (Join-Path $out "scheduledtask_list.csv") -NoTypeInformation -Force
  Get-CimInstance Win32_Service | Select Name, DisplayName, PathName, StartMode, State | Export-Csv -Path (Join-Path $out "services_list.csv") -NoTypeInformation -Force
} catch {
  Save-ObjectToFile -obj ("Failed to dump process/task/service lists: $_") -name "lists_error.txt"
}

# 13) Export Event logs (Security/System/Application)
try {
  wevtutil epl Security (Join-Path $out "Security.evtx")
  wevtutil epl System (Join-Path $out "System.evtx")
  wevtutil epl Application (Join-Path $out "Application.evtx")
  Save-ObjectToFile -obj "Exported Security/System/Application logs to EVTX files." -name "evtx_export_info.txt"
} catch {
  Save-ObjectToFile -obj ("Failed to export event logs: $_") -name "evtx_export_info.txt"
}

# 14)
