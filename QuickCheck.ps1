# Quick check for RDP (3389) and WinRM (5985/5986)

Write-Host "=== Service Status ==="
Get-Service -Name TermService, WinRM | Select-Object Name, Status, StartType

Write-Host "`n=== Listening Ports ==="
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 3389,5985,5986 } |
    Select-Object LocalAddress, LocalPort, State, OwningProcess
