## Unblock files
Get-ChildItem -Path $PSScriptRoot -Recurse -File | Unblock-File

## dot source all script files
Get-ChildItem -Path $PSScriptRoot -Recurse -File -Filter '*.ps1' | ForEach-Object {
    if($_.DirectoryName -imatch '.+\\poshkeepass\\(functions|internal)$')
    {
        . $_.FullName
    }
}

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
else
{
    New-Variable -Name 'KeePassProfileNames' -Value @((Get-KeePassDatabaseConfiguration).Name) -Scope 'Script' #-Option Constant
}

Export-ModuleMember *
