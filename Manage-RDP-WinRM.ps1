<#
.SYNOPSIS
  Menu to manage RDP (TermService) and WinRM services.
#>

function Show-Menu {
    Clear-Host
    Write-Host "==============================="
    Write-Host "   RDP & WinRM Service Manager"
    Write-Host "==============================="
    Write-Host "1. Check service status"
    Write-Host "2. Stop a service"
    Write-Host "3. Disable a service (no start on reboot)"
    Write-Host "4. Enable & start a service"
    Write-Host "5. Exit"
    Write-Host "==============================="
}

function Check-Status {
    Write-Host "`n--- Service Status ---"
    Get-Service -Name TermService, WinRM | Select-Object Name, Status, StartType
    Pause
}

function Stop-ServiceMenu {
    Write-Host "`nStop which service?"
    Write-Host "1. RDP (TermService)"
    Write-Host "2. WinRM"
    $choice = Read-Host "Enter choice"
    switch ($choice) {
        "1" { Stop-Service -Name TermService -Force ; Write-Host "RDP stopped." }
        "2" { Stop-Service -Name WinRM -Force ; Write-Host "WinRM stopped." }
        default { Write-Host "Invalid choice." }
    }
    Pause
}

function Disable-ServiceMenu {
    Write-Host "`nDisable which service?"
    Write-Host "1. RDP (TermService)"
    Write-Host "2. WinRM"
    $choice = Read-Host "Enter choice"
    switch ($choice) {
        "1" { Set-Service -Name TermService -StartupType Disabled ; Write-Host "RDP disabled." }
        "2" { Set-Service -Name WinRM -StartupType Disabled ; Write-Host "WinRM disabled." }
        default { Write-Host "Invalid choice." }
    }
    Pause
}

function Enable-ServiceMenu {
    Write-Host "`nEnable & start which service?"
    Write-Host "1. RDP (TermService)"
    Write-Host "2. WinRM"
    $choice = Read-Host "Enter choice"
    switch ($choice) {
        "1" { Set-Service -Name TermService -StartupType Automatic ; Start-Service -Name TermService ; Write-Host "RDP enabled & started." }
        "2" { Set-Service -Name WinRM -StartupType Automatic ; Start-Service -Name WinRM ; Write-Host "WinRM enabled & started." }
        default { Write-Host "Invalid choice." }
    }
    Pause
}

# --- Main Loop ---
do {
    Show-Menu
    $selection = Read-Host "Choose an option (1-5)"
    switch ($selection) {
        "1" { Check-Status }
        "2" { Stop-ServiceMenu }
        "3" { Disable-ServiceMenu }
        "4" { Enable-ServiceMenu }
        "5" { Write-Host "Exiting..." }
        default { Write-Host "Invalid selection."; Pause }
    }
} until ($selection -eq "5")
