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
    [CmdletBinding(DefaultParameterSetName = '__None')]
    param
    (
        [Parameter(Position = 0, ParameterSetName = '__Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, ParameterSetName = '__DefaultDB')]
        [ValidateNotNullOrEmpty()]
        [Switch] $Default,

        [Parameter(Position = 2)]
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
            elseif($Default)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Default -ieq 'true' }

                if($Stop -and -not $ProfileResults)
                {
                    throw 'Unable to find a default KeePass Configuration, please specify a database profile name or set a default profile.'
                }
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
                $ProfileDefault = if($ProfileResult.Default -eq 'True'){$true}else{$false}

                [hashtable] $ProfileObject = [ordered]@{
                    'Name'               = $ProfileResult.Name;
                    'DatabasePath'       = $ProfileResult.DatabasePath;
                    'KeyPath'            = $ProfileResult.KeyPath;
                    'UseMasterKey'       = $UseMasterKey;
                    'UseNetworkAccount'  = $UseNetworkAccount;
                    'AuthenticationType' = $ProfileResult.AuthenticationType;
                    'Default'            = $ProfileDefault;
                }

                New-Object -TypeName PSObject -Property $ProfileObject
            }
        }
        else
        {
            Write-Warning 'The specified KeePass Configuration does not exist.'
        }
    }
}
