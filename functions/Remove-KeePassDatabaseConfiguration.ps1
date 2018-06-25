function Remove-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Configuration Profile.
        .DESCRIPTION
            This function allows a specified database configuration profile to be removed from the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to be deleted.
        .EXAMPLE
            PS> Remove-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example will remove the database configuration profile 'Personal' from the KeePassConfiguration.xml file.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string] $DatabaseProfileName
    )
    begin
    {
    }
    process
    {
        if($PSCmdlet.ShouldProcess($DatabaseProfileName))
        {
            try
            {
                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($Global:KeePassConfigurationFile)
                $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -eq $DatabaseProfileName } | ForEach-Object { $xml.Settings.DatabaseProfiles.RemoveChild($_) } | Out-Null
                $XML.Save($Global:KeePassConfigurationFile)
            }
            catch
            {
                Write-Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Database Configuration Profile ({0}).' -f $DatabaseProfileName)
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}
