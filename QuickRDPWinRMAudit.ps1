<#
.SYNOPSIS
  Quick audit for RDP and WinRM misconfigurations on Windows Server.
  Checks RDP status, NLA, listening ports, WinRM listeners, and authorized users.
#>

# --- Setup output ---
$desktop = [Environment]::GetFolderPath('Desktop')
$outFile = Join-Path $desktop "RDP_WinRM_Audit.txt"

Function Write-Log { param($s) ; $s | Out-File -FilePath $outFile -Append -Encoding utf8 ; Write-Host $s }

Write-Log "=== RDP & WinRM Quick Audit - $(Get-Date) ===`n"

# --- 1. RDP Status ---
Write-Log "--- RDP Status ---"
try {
    $rdpService = Get-Service -Name TermService -ErrorAction Stop
    Write-Log "RDP Service (TermService): $($rdpService.Status)"
} catch {
    Write-Log "RDP Service not found."
}

# Check if Network Level Authentication (NLA) is enabled
try {
    $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication
    if ($nla.UserAuthentication -eq 1) { $nlaStatus = "Enabled" } else { $nlaStatus = "Disabled" }
    Write-Log "Network Level Authentication (NLA): $nlaStatus"
} catch {
    Write-Log "Unable to read NLA setting."
}

# --- 2. RDP Listening Ports ---
Write-Log "`n--- RDP Listening Ports ---"
$rdpPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -eq 3389}
if ($rdpPorts) {
    $rdpPorts | ForEach-Object { Write-Log ("Port {0} on {1} - PID {2}" -f $_.LocalPort, $_.LocalAddress, $_.OwningProcess) }
} else { Write-Log "No RDP port 3389 listening." }

# --- 3. WinRM Status ---
Write-Log "`n--- WinRM Status ---"
try {
    $winrmService = Get-Service -Name WinRM -ErrorAction Stop
    Write-Log "WinRM Service: $($winrmService.Status)"
} catch {
    Write-Log "WinRM Service not found."
}

# --- 4. WinRM Listeners ---
Write-Log "`n--- WinRM Listeners ---"
try {
    $listeners = winrm enumerate winrm/config/listener
    Write-Log $listeners
} catch {
    Write-Log "Failed to enumerate WinRM listeners."
}

# --- 5. Users Allowed to RDP / WinRM ---
Write-Log "`n--- Users Allowed for Remote Access ---"

# RDP: members of Remote Desktop Users group
try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" | Select Name,ObjectClass
    if ($rdpUsers) {
        $rdpUsers | ForEach-Object { Write-Log ("RDP User: {0} ({1})" -f $_.Name, $_.ObjectClass) }
    } else { Write-Log "No users in Remote Desktop Users group." }
} catch { Write-Log "Cannot retrieve Remote Desktop Users." }

# WinRM: users with remote access (Administrators can always use WinRM)
try {
    $admins = Get-LocalGroupMember -Group "Administrators" | Select Name,ObjectClass
    $admins | ForEach-Object { Write-Log ("WinRM Admin User: {0} ({1})" -f $_.Name, $_.ObjectClass) }
} catch { Write-Log "Cannot retrieve Administrators group members." }

Write-Log "`nAudit complete. Results saved to: $outFile"
Invoke-Item -Path $outFile
