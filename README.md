# DPAPI_SECRETS-from-PS1
Disclaimer: This repository is provided for educational research and penetration testing purposes only. Unauthorized use against systems without explicit permission is illegal and unethical. By using this software, you agree that you are responsible for your actions.

## Overview
This PowerShell project is designed to extract Windows credentials and Wi-Fi profiles from local systems by leveraging the DPAPI. It combines automated Windows Vault extraction and Wi-Fi password decryption. As of now, these scripts are not detected by Windows Defender.

## Components
### main.ps1
- Purpose: Entry point script with automatic privilege escalation check.
- Functionality:
  - Verifies if the current user has Administrator privileges.
  - Launches windows_vault.ps1 to extract Windows Vault secrets.
  - Schedules and executes wifi.ps1 using the SYSTEM account to ensure access to Wi-Fi credentials.
  - Cleans up temporary scheduled tasks automatically.
- Output: Saves all extracted data to DPAPI_dumps on the active user's desktop.

### windows_vault.ps1
- Purpose: Extract Windows Vault credentials and DPAPI-protected files.
- Capabilities:
  - Uses Get-StoredCredential for Generic, Domain, and Web vault entries.
  - Reads raw DPAPI blobs from AppData\Microsoft\Credentials.
  - Decrypts secrets with CryptUnprotectData using native .NET interop.
  - Exports results in CSV and JSON formats under DPAPI_dumps/vault.
- Notes:
  - Implements hex-to-byte conversion and memory management to avoid leaks.
  - Supports both UTF-8 and UTF-16 encoded secrets.

### wifi.ps1
- Purpose: Extract all saved Wi-Fi profiles and passwords.
- Capabilities:
  - Recursively enumerates C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces.
  - Parses XML WLAN profiles to retrieve SSID, authentication type, encryption, and password.
  - Automatically decrypts DPAPI-protected Wi-Fi keys.
  - Exports results in CSV and JSON formats under DPAPI_dumps/wifi.
- Notes:
  - Uses a custom DPAPI interop class for low-level memory-safe decryption.
  - Encodes output in UTF-8 for cross-platform compatibility.
  - Designed to run as SYSTEM to bypass user-level restrictions.

## How to launch
- First, lauch PowerShell as admin
- Go to the folder path
- ``powershell -ExecutionPolicy Bypass -File .\main.ps1``
