[Cmdletbinding()]
param
(
    $BuildPath
)

if(-not $BuildPath)
{
    Write-Verbose -Message 'Setting up Build Path'
    $RawPSD = Get-Content -Path "$($PSScriptRoot)\PoShKeePass.psd1"
    $ModuleVersion = ($RawPSD | ? { $_ -match "^\s+ModuleVersion.+$" }) -replace '.+(\d\.\d\.\d\.\d).$', '$1'
    $BuildPath = ('{0}\build\{1}\PoShKeePass' -f $PSScriptRoot, $ModuleVersion)

    if(Test-Path $BuildPath)
    {
        Get-ChildItem -Path $BuildPath -Recurse | Remove-Item -Recurse -Force
    }
    else
    {
        New-Item -Path $BuildPath -ItemType Directory -Force
    }
}

New-Item -Path $BuildPath -Name 'bin' -ItemType Directory -Force

[string] $ModuleFile = '{0}\PoShKeePass.psm1' -f $BuildPath
[string] $ManifestFile = '{0}\PoShKeePass.psd1' -f $PSScriptRoot
[string] $ChangeLogFile = '{0}\changelog.md' -f $PSScriptRoot
[string] $LicenseFile = '{0}\license' -f $PSScriptRoot
[string] $FormatFile = '{0}\PoShKeePass.format.ps1xml' -f $PSScriptRoot
[string] $ReadMeFile = '{0}\readme.md' -f $PSScriptRoot
[string] $Bin = '{0}\bin\KeePassLib.dll' -f $PSScriptRoot

[string[]] $RootFilesToCopy = @($ManifestFile, $ChangeLogFile, $LicenseFile, $FormatFile, $ReadMeFile)


Get-ChildItem -Path $PSScriptRoot -Recurse -File -Filter '*.ps1' | ForEach-Object {
    if($_.DirectoryName -imatch '.+\\poshkeepass\\(functions|internal)$')
    {
        Write-Verbose -Message "Processing File: $($_.FullName)"
        Get-Content -Path $_.FullName | Add-Content -Path $ModuleFile -Force
    }
}

Write-Verbose -Message 'Adding tail to module file.'
@'

## Source KpLib
Import-KPLibrary

[String] $Global:KeePassConfigurationFile = '{0}\KeePassConfiguration.xml' -f $PSScriptRoot

## Check fo config and init
if (-not(Test-Path -Path $Global:KeePassConfigurationFile))
{
    Write-Warning -Message '**IMPORTANT NOTE:** Please always keep an up-to-date backup of your keepass database files and key files if used.'
    Write-Warning -Message 'This message will not show again on next import.'
    if(-not $(Restore-KPConfigurationFile))
    {
        New-KPConfigurationFile
    }
}

'@ | Add-Content -Path $ModuleFile -Force

Write-Verbose -Message 'Copying root dir files over'
$RootFilesToCopy | ForEach-Object {
    Copy-Item -Path $_ -Destination $BuildPath
}

Write-Verbose -Message 'Copying Bin files'
Copy-Item -Path $Bin -Destination "$BuildPath\bin" -Force