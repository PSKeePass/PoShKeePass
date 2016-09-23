## Get psd1 file
$RawPSD = Get-Content -Path "$($PSScriptRoot)\..\PSKeePass.psd1"
$ModuleVersion=($RawPSD | ? { $_ -match "^ModuleVersion.*$" }) -replace "^.*=\s|'"

[Int[]] $VerArr = $ModuleVersion -split '\.'

$NewModuleVersion = ''
$CarryValue = 1
$EntryPoint = $($VerArr.Count -1)
for($i=$EntryPoint; $i -ge 0; $i--){
    $VersionPart = $VerArr[$i]

    $VersionPart += $CarryValue

    if($i -eq 0)
    {
        $NewModuleVersion = "$VersionPart"+$NewModuleVersion
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
        $NewModuleVersion = ".$VersionPart"+$NewModuleVersion
    }
}

Write-Verbose -Message "New Version: $NewModuleVersion"

$RawPSD | % { $_ -replace "(?<=^ModuleVersion = ')\d+\.\d\.\d\.\d(?=')",$NewModuleVersion } | Out-File -FilePath  "$($PSScriptRoot)\..\PSKeePass.psd1" -Force