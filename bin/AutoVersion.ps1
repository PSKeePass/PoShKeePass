[Cmdletbinding()]
param()

## Get psd1 file
$RawPSD = Get-Content -Path "$($PSScriptRoot)\..\PoShKeePass.psd1"
$ModuleVersion = ($RawPSD | Where-Object { $_ -match "^\s+ModuleVersion.+$" }) -replace '.+(\d\.\d\.\d\.\d).$', '$1'

Write-Verbose -Message ('ModuleVersion Found: ' + $ModuleVersion)
[Int[]] $VerArr = $ModuleVersion -split '\.'

$NewModuleVersion = ''
$CarryValue = 1
$EntryPoint = $($VerArr.Count - 1)

for($i = $EntryPoint; $i -ge 0; $i--)
{
    $VersionPart = $VerArr[$i]

    $VersionPart += $CarryValue

    if($i -eq 0)
    {
        $NewModuleVersion = "$VersionPart" + $NewModuleVersion
        break
    }
    else
    {
        if($VersionPart -eq 10)
        {
            $VersionPart = 0
        }
        else
        {
            $CarryValue = 0
        }
        $NewModuleVersion = ".$VersionPart" + $NewModuleVersion
    }
}

Write-Verbose -Message "New Version: $NewModuleVersion"

$RawPSD | ForEach-Object { $_ -replace $ModuleVersion, $NewModuleVersion } | Out-File -FilePath  "$($PSScriptRoot)\..\PoShKeePass.psd1" -Force