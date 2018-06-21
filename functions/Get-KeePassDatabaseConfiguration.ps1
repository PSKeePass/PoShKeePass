function Get-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .DESCRIPTION
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to lookup.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration

            This Example will return all Database Configuration Profiles if any.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example returns the Database Configuration Profile with the name Personal.
        .INPUTS
            Strings
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1)]
        [Switch] $Stop
    )
    process
    {
        if(Test-Path -Path $Global:KeePassConfigurationFile)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($Global:KeePassConfigurationFile)

            if($DatabaseProfileName)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -ilike $DatabaseProfileName }
            }
            else
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile
            }

            if(-not $ProfileResults -and $Stop)
            {
                throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            }

            foreach($ProfileResult in $ProfileResults)
            {
                $UseNetworkAccount = if($ProfileResult.UseNetworkAccount -eq 'True'){$true}else{$false}
                $UseMasterKey = if($ProfileResult.UseMasterKey -eq 'True'){$true}else{$false}

                [hashtable] $ProfileObject = [ordered]@{
                    'Name'               = $ProfileResult.Name;
                    'DatabasePath'       = $ProfileResult.DatabasePath;
                    'KeyPath'            = $ProfileResult.KeyPath;
                    'UseMasterKey'       = $UseMasterKey;
                    'UseNetworkAccount'  = $UseNetworkAccount;
                    'AuthenticationType' = $ProfileResult.AuthenticationType;
                }

                New-Object -TypeName PSObject -Property $ProfileObject
            }
        }
        else
        {
            Write-Warning 'No KeePass Configuration has been created.'
        }
    }
}
