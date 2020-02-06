[Cmdletbinding()]
param
(
    $BuildPath
)

if(-not $BuildPath)
{
    Write-Verbose -Message 'Setting up Build Path'
    $RawPSD = Get-Content -Path "$($PSScriptRoot)\PoShKeePass.psd1"
    $ModuleVersion = ($RawPSD | Where-Object { $_ -match "^\s+ModuleVersion.+$" }) -replace '.+(\d\.\d\.\d\.\d).$', '$1'
    $BuildPath = ('{0}\build\PoShKeePass\{1}' -f $PSScriptRoot, $ModuleVersion)

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
[string] $Bin = '{0}\bin\KeePassLib*.dll' -f $PSScriptRoot

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

[String] $Global:KeePassConfigurationFile = '{0}\KeePassConfiguration.xml' -f $PSScriptRoot
# Check, if configuration file is writeable, otherwise use %APPDATA%\PoShKeePass\KeePassConfiguration.xml
try
{
    [IO.File]::OpenWrite($Global:KeePassConfigurationFile).close()
    # The OpenWrite may have created the configuration file, so an empty file will be deleted
    If((Get-Content $Global:KeePassConfigurationFile).Length -eq 0)
    {
        Remove-Item $Global:KeePassConfigurationFile
    }

}
catch
{
    if(-not (Test-Path ("{0}\PoShKeePass" -f $env:APPDATA)))
    {
        New-Item -ItemType Directory ("{0}\PoShKeePass" -f $env:APPDATA)
    }
    $Global:KeePassConfigurationFile = "$env:APPDATA\PoShKeePass\KeePassConfiguration.xml"
}
#If the configuration file does not exist, create a new one
if(-not (Test-Path $Global:KeePassConfigurationFile))
{
    [xml]$newData = New-Object System.Xml.XmlDocument
    $newData.AppendChild($newData.CreateXmlDeclaration("1.0", $null, $null))
    $newData.AppendChild($newData.CreateProcessingInstruction("xml-stylesheet", "type='text/xsl' href='style.xsl'"))
    $newRoot = $newData.CreateNode("element", "Settings", $null)
    $newRoot.AppendChild($newData.CreateNode("element", "DatabaseProfiles", $null))
    $newRoot.AppendChild($newData.CreateNode("element", "PasswordProfiles", $null))
    $newData.AppendChild($newRoot)
    $newData.Save($Global:KeePassConfigurationFile)
}

[String] $Global:KeePassLibraryPath = '{0}\bin\KeePassLib_2.39.1.dll' -f $PSScriptRoot

## Source KpLib
Import-KPLibrary

## Check fo config and init
if (-not(Test-Path -Path $Global:KeePassConfigurationFile))
{
    Write-Warning -Message '**IMPORTANT NOTE:** Please always keep an up-to-date backup of your keepass database files and key files if used.'

    $Versions = ((Get-ChildItem "$PSScriptRoot\..").Name | Sort-Object -Descending)

    if(-not $(Restore-KPConfigurationFile))
    {
        New-KPConfigurationFile

        $previousVersion = [int]($Versions[1] -replace '\.')
        $CurrentVersion = $Versions[0]
        if($previousVersion -lt 2124)
        {
            Write-Warning -Message ('**BREAKING CHANGES:** This new version of the module {0} contains BREAKING CHANGES, please review the changelog or readme for details!' -f $CurrentVersion)
        }

        Write-Warning -Message 'This message will not show again on next import.'
    }
}
else
{
    New-Variable -Name 'KeePassProfileNames' -Value @((Get-KeePassDatabaseConfiguration).Name) -Scope 'Script' #-Option Constant
}

Export-ModuleMember *

if(Get-Command Register-ArgumentCompleter -ea 0)
{
    Register-ArgumentCompleter -ParameterName 'DatabaseProfileName' -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

        Get-KeePassDatabaseConfiguration | Where-Object { $_.Name -ilike "${wordToComplete}*" } | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult ( $_.Name, $_.Name, 'ParameterValue', $_.Name)
        }
    }

    Register-ArgumentCompleter -ParameterName 'IconName' -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

        [KeePassLib.PwIcon].GetEnumValues() | Where-Object { $_ -ilike "${wordToComplete}*" } | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult ( $_, $_, 'ParameterValue', $_)
        }
    }

    Register-ArgumentCompleter -ParameterName 'PasswordProfileName' -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

        (Get-KPPasswordProfile).Name | Where-Object { $_ -ilike "${wordToComplete}*" } | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult ( $_, $_, 'ParameterValue', $_)
        }
    }
}

'@ | Add-Content -Path $ModuleFile -Force

Write-Verbose -Message 'Copying root dir files over'
$RootFilesToCopy | ForEach-Object {
    Copy-Item -Path $_ -Destination $BuildPath
}

Write-Verbose -Message 'Copying Bin files'
Copy-Item -Path $Bin -Destination "$BuildPath\bin" -Force
