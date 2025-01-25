$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {
    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Firma no válida (Error desconocido)"

    if ($Existence) {
        switch ($Authenticode) {
            "Valid" { $Signature = "Firma válida" }
            "NotSigned" { $Signature = "Firma no válida (No está firmado)" }
            "HashMismatch" { $Signature = "Firma no válida (HashMismatch)" }
            "NotTrusted" { $Signature = "Firma no válida (No confiable)" }
            "UnknownError" { $Signature = "Firma no válida (Error desconocido)" }
        }
    } else {
        $Signature = "El archivo no fue encontrado"
    }

    return $Signature
}

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

Clear-Host

if (!(Test-Admin)) {
    Write-Warning "Por favor, ejecuta este script como administrador."
    Start-Sleep 10
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
    try {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
    } catch {
        Write-Warning "Error montando HKEY_LOCAL_MACHINE"
        Exit
    }
}

$bamPaths = @("bam", "bam\State")
try {
    $Users = foreach ($path in $bamPaths) {
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$path\UserSettings\" | Select-Object -ExpandProperty PSChildName
    }
} catch {
    Write-Warning "Error al parsear la clave BAM. Es posible que tu versión de Windows no sea compatible."
    Exit
}

$registryPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\",
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\"
)

$timeZoneInfo = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
$userTimeZone = $timeZoneInfo.TimeZoneKeyName
$userBias = $timeZoneInfo.ActiveTimeBias
$userDaylightBias = $timeZoneInfo.DaylightBias

$Bam = foreach ($Sid in $Users) {
    foreach ($rp in $registryPaths) {
        $BamItems = Get-Item -Path "$rp\UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        Write-Host "Procesando entradas en $rp\UserSettings\$Sid" -ForegroundColor Green

        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $User = "Desconocido"
        }

        foreach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$rp\UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
            if ($Key.Length -eq 24) {
                $Hex = [System.BitConverter]::ToString($Key[7..0]) -replace "-", ""
                $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).AddMinutes($userBias) -Format "yyyy-MM-dd HH:mm:ss")
                $FilePath = "C:\" + ($Item.TrimStart("\Device\HarddiskVolume"))

                [PSCustomObject]@{
                    'Hora local del examinador' = $TimeLocal
                    'Hora de última ejecución (UTC)' = $TimeUTC
                    'Hora de última ejecución (Zona del usuario)' = $TimeUser
                    'Aplicación' = Split-Path -Leaf $FilePath
                    'Ruta' = $FilePath
                    'Firma' = Get-Signature -FilePath $FilePath
                    'Usuario' = $User
                    'SID' = $Sid
                }
            }
        }
    }
}

$Bam | Out-GridView -PassThru -Title "Entradas BAM: $($Bam.Count) - Zona Horaria: ($userTimeZone)"

$sw.Stop()
$elapsedTime = $sw.Elapsed.TotalMinutes
Write-Host "Tiempo de ejecución: $elapsedTime minutos" -ForegroundColor Yellow
