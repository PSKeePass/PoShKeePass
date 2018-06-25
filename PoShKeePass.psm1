## Unblock files
Get-ChildItem -Path $PSScriptRoot -Recurse -File | Unblock-File

## dot source all script files
Get-ChildItem -Path $PSScriptRoot -Recurse -File -Filter '*.ps1' | ForEach-Object {
    if($_.DirectoryName -imatch '.+\\poshkeepass\\(functions|internal)$')
    {
        . $_.FullName
    }
}


[String] $Global:KeePassConfigurationFile = '{0}\KeePassConfiguration.xml' -f $PSScriptRoot
[String] $Global:KeePassLibraryPath = '{0}\bin\KeePassLib_2.39.1.dll' -f $PSScriptRoot

## Source KpLib
Import-KPLibrary

## Check for config and init
if (-not(Test-Path -Path $Global:KeePassConfigurationFile))
{
    Write-Warning -Message '**IMPORTANT NOTE:** Please always keep an up-to-date backup of your keepass database files and key files if used.'

    $CurrentVersion = ((Get-ChildItem "$PSScriptRoot\..").Name | Sort-Object -Descending | Select-Object -First 2)[0]

    if($CurrentVersion -eq '2.1.1.8')
    {
        Write-Warning -Message ('**BREAKING CHANGES:** This new version of the module {0} contains BREAKING CHANGES, please review the changelog or readme for details!' -f $CurrentVersion)
    }

    Write-Warning -Message 'This message will not show again on next import.'

    if(-not $(Restore-KPConfigurationFile))
    {
        New-KPConfigurationFile
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

## add one for paths - can't do this until connection management is implemented.
