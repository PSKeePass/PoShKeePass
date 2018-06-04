function Get-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .DESCRIPTION
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to lookup.
            Note this is a Dynamic Parameter and will only be available if there are profiles in the KeePassConfiguration.xml.
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
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName
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

            foreach($ProfileResult in $ProfileResults)
            {
                $UseNetworkAccount = if($ProfileResult.UseNetworkAccount -eq 'True'){$true}else{$false}
                $UseMasterKey = if($ProfileResult.UseMasterKey -eq 'True'){$true}else{$false}

                $ProfileObject = New-Object -TypeName PSObject
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'Name' -Value $ProfileResult.Name
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'DatabasePath' -Value $ProfileResult.DatabasePath
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'KeyPath' -Value $ProfileResult.KeyPath
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'UseMasterKey' -Value $UseMasterKey
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'UseNetworkAccount' -Value $UseNetworkAccount
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'AuthenticationType' -Value $ProfileResult.AuthenticationType
                $ProfileObject
            }
        }
        else
        {
            Write-Warning 'No KeePass Configuration has been created.'
        }
    }
}
