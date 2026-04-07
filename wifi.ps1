[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class DPAPI
{
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        StringBuilder ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut
    );
}
"@

function Convert-HexToBytes {
    param([Parameter(Mandatory)][string]$Hex)

    $Hex = $Hex -replace '\s',''
    if ($Hex.Length % 2 -ne 0) {
        throw "Hex string invalide"
    }

    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i*2,2),16)
    }
    return $bytes
}

function Unprotect-DPAPI {
    param([Parameter(Mandatory)][string]$HexString)

    $inBlob  = New-Object "DPAPI+DATA_BLOB"
    $outBlob = New-Object "DPAPI+DATA_BLOB"

    try {
        $bytes = Convert-HexToBytes $HexString

        $inBlob.cbData = $bytes.Length
        $inBlob.pbData = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $inBlob.pbData, $bytes.Length)

        $success = [DPAPI]::CryptUnprotectData(
            [ref]$inBlob,
            $null,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            0,
            [ref]$outBlob
        )

        if (-not $success) {
            return $null
        }


		$outBytes = New-Object byte[] $outBlob.cbData
		[Runtime.InteropServices.Marshal]::Copy($outBlob.pbData, $outBytes, 0, $outBlob.cbData)

		if ($outBytes.Length -ge 2 -and $outBytes[0] -eq 0xFF -and $outBytes[1] -eq 0xFE) {
			$password = [Text.Encoding]::Unicode.GetString($outBytes).Trim([char]0)
		} else {
			$password = [Text.Encoding]::UTF8.GetString($outBytes).Trim([char]0)
		}

		return $password

    }
    catch {
        Write-Verbose "DPAPI error: $_"
        return $null
    }
    finally {
        if ($inBlob.pbData -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($inBlob.pbData)
        }
        if ($outBlob.pbData -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($outBlob.pbData)
        }
    }
}

function Get-WifiProfiles {
    [CmdletBinding()]
    param(
        [string]$Path = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"
    )

    if (-not (Test-Path $Path)) {
        throw "Chemin introuvable: $Path"
    }

    foreach ($file in Get-ChildItem -Recurse -Path $Path -Filter *.xml -ErrorAction SilentlyContinue) {
        try {
            $xml = [xml](Get-Content $file.FullName -ErrorAction Stop)

            $profile = $xml.WLANProfile
            if (-not $profile) { continue }

            $security = $profile.MSM.security
            $sharedKey = $security.sharedKey

            $ssid = $profile.name
            $auth = $security.authEncryption.authentication
            $cipher = $security.authEncryption.encryption

            $key = $sharedKey.keyMaterial
            $protected = $sharedKey.protected

            $password = $null

            if ($key) {
                if ($protected -eq "true") {
                    $password = Unprotect-DPAPI $key
                } else {
                    $password = $key
                }
            }

            [PSCustomObject]@{
                SSID           = $ssid
                Authentication = $auth
                Encryption     = $cipher
                Password       = $password
                SourceFile     = $file.FullName
            }
        }
        catch {
            Write-Verbose "Erreur fichier: $($file.FullName)"
        }
    }
}


function Get-ActiveUserDesktop {
    try {
        $user = (Get-CimInstance Win32_ComputerSystem).UserName

        if ($user) {
            $username = $user.Split('\')[1]
            return "C:\Users\$username\Desktop"
        }
    } catch {}

    return [Environment]::GetFolderPath("Desktop")
}

function Export-WifiResults {
    param(
        [Parameter(Mandatory)]$Data,
        [string]$BaseDir = (Get-ActiveUserDesktop)
    )

    $resultsDir = Join-Path $BaseDir "DPAPI_dumps"
    $wifiDir    = Join-Path $resultsDir "wifi"

    if (-not (Test-Path $resultsDir)) {
        New-Item -ItemType Directory -Path $resultsDir | Out-Null
    }

    if (-not (Test-Path $wifiDir)) {
        New-Item -ItemType Directory -Path $wifiDir | Out-Null
    }

    $csvPath  = Join-Path $wifiDir "wifi_dump.csv"
    $jsonPath = Join-Path $wifiDir "wifi_dump.json"

    $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Data | ConvertTo-Json -Depth 3 | Out-File $jsonPath -Encoding UTF8
}


# ===============================
# Launch
# ===============================
$results = Get-WifiProfiles
Export-WifiResults -Data $results