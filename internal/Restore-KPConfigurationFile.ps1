function Restore-KPConfigurationFile
{
    <#
        .SYNOPSIS
            Restore Config file from previous version
        .DESCRIPTION
            Restore Config file from previous version
        .PARAMETER
        .EXAMPLE
        .NOTES
        .INPUTS
        .OUTPUTS
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [String] $BreakingChangesVersion
    )
    process
    {
        $ReturnStatus = $false
        $Path = Resolve-Path -Path ('{0}\..' -f $PSScriptRoot)

        Write-Verbose -Message ('[PROCESS] Checking if there is a previous KeePassConfiguration.xml file to be loaded from: {0}.' -f $Path.Path )
        $PreviousVersion = ((Get-ChildItem $Path.Path).Name | Sort-Object -Descending | Select-Object -First 2)[1]

        Write-Verbose -Message ('PreviousVersion: {0}.' -f $PreviousVersion)
        $PreviousVersionConfigurationFile = Resolve-Path -Path ('{0}\..\{1}\KeePassConfiguration.xml' -f $PSScriptRoot, $PreviousVersion) -ErrorAction SilentlyContinue -ErrorVariable GetPreviousConfigurationFileError

        if(-not $GetPreviousConfigurationFileError -and $PreviousVersion)
        {
            Write-Verbose -Message ('[PROCESS] Copying last Configuration file from the previous version ({0}).' -f $PreviousVersion)
            Copy-Item -Path $PreviousVersionConfigurationFile -Destination "$PSScriptRoot" -ErrorAction SilentlyContinue -ErrorVariable RestorePreviousConfigurationFileError

            if($RestorePreviousConfigurationFileError)
            {
                Write-Warning -Message '[PROCESS] Unable to restore previous KeePassConfiguration.xml file. You will need to copy your previous file from your previous module version folder or create a new one.'
            }
            else
            {
                $ReturnStatus = $true
            }
        }

        return $ReturnStatus
    }
}
