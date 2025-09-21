# Audit-Indigo.ps1
param(
  [string]$Path = "C:\Tools\Indigo"
)

if (-not (Test-Path $Path)) { Write-Host "Path not found: $Path"; exit 1 }

$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$out = "C:\Users\Public\Indigo_Audit_$ts"
New-Item -Path $out -ItemType Directory -Force | Out-Null

Function Save { param($name,$obj) ; $obj | Out-File -FilePath (Join-Path $out $name) -Encoding utf8 }

# 1) file listing
$files = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | 
  Select FullName, Length, LastWriteTime, Attributes
Save "file_list.txt" $files

# 2) hashes
$hashes = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ Path = $_.FullName; SHA256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash; Size = $_.Length; LastWrite = $_.LastWriteTime }
}
Save "hashes.txt" $hashes

# 3) signatures for exes/dlls
$sigs = Get-ChildItem -Path $Path -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.FullName
  [PSCustomObject]@{ Path = $_.FullName; Signer = ($sig.SignerCertificate.Subject -join ';'); Status = $sig.Status }
}
Save "signatures.txt" $sigs

# 4) check process usage referencing path
$procs = Get-CimInstance Win32_Process | Where-Object {
  ($_.ExecutablePath -and $_.ExecutablePath -like "$Path*") -or ($_.CommandLine -and $_.CommandLine -like "*Indigo*")
} | Select ProcessId, Name, ExecutablePath, CommandLine
Save "processes_using_indigo.txt" $procs

# 5) scheduled tasks referencing path
$stasks = Get-ScheduledTask | Where-Object { 
  $_.Actions.ToString() -match [Regex]::Escape($Path) -or $_.TaskPath -match 'Indigo' 
} | Select TaskName, TaskPath, Author, State
Save "scheduledtasks.txt" $stasks

# 6) service definitions referencing path
$svcs = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*Indigo*" } | Select Name, DisplayName, PathName, StartMode, State
Save "services.txt" $svcs

# 7) registry run keys referencing path
$runHKLM = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue | Out-String)
$runHKCU = (Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue | Out-String)
$runHKLM | Out-File -FilePath (Join-Path $out "run_hklm.txt")
$runHKCU | Out-File -FilePath (Join-Path $out "run_hkcu.txt")

# 8) quick text search inside scripts for indicators
$patterns = 'EncodedCommand','Invoke-WebRequest','Invoke-Expression','DownloadString','Base64','cobalt','beacon','meterpreter','mimikatz'
$search = Get-ChildItem -Path $Path -Recurse -Include *.ps1,*.bat,*.cmd,*.vbs -ErrorAction SilentlyContinue |
  Select-String -Pattern $patterns -SimpleMatch | Select Path, LineNumber, Line
Save "script_search.txt" $search

# 9) ACLs
$acls = Get-ChildItem -Path $Path -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ Path = $_.FullName; ACL = (Get-Acl $_.FullName).AccessToString }
}
Save "acls.txt" $acls

Write-Host "Audit saved to $out. Review the files in that directory."
Invoke-Item -Path $out
