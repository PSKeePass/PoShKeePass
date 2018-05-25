function Get-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to Retreive All or a Specified Password Profile.
        .DESCRIPTION
            Function to Retreive All or a Specified Password Profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile Name to Retreive.
        .EXAMPLE
            PS> Get-KPPasswordProfile

            Returns all Password Profile definitions if any.
        .NOTES
            Internal Funciton.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    process
    {
        if(Test-Path -Path $Global:KeePassConfigurationFile)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($Global:KeePassConfigurationFile)
            if($PasswordProfileName)
            {
                $XML.Settings.PasswordProfiles.Profile | Where-Object { $_.Name -ilike $PasswordProfileName}
            }
            else
            {
                $XML.Settings.PasswordProfiles.Profile
            }
        }
        else
        {
            Write-Verbose 'No KeePass Configuration has been created.'
        }
    }
}
