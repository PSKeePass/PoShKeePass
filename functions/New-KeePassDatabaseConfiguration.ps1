function New-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Create or Add a new KeePass Database Configuration Profile to the KeePassConfiguration.xml
        .DESCRIPTION
            The Profile Created will be accessible from the core functions Get,Update,New,Remove KeePassEntry and ect.
            The Profile stores database configuration for opening and authenticating to a keepass database.
            Using the configuration allows for speedier authentication and less complex commands.
        .PARAMETER DatabaseProfileName
            Specify the Name of the new Database Configuration Profile.
        .PARAMETER DatabasePath
            Specify the Path to the database (.kdbx) file.
        .PARAMETER KeyPath
            Specify the Path to the database (.key) key file if there is one.
        .PARAMETER UseNetworkAccount
            Specify this flag if the database uses NetworkAccount Authentication.
        .PARAMETER UseMasterKey
            Specify this flag if the database uses a Master Key Password for Authentication.
        .PARAMETER PassThru
            Specify to return the new database configuration profile object.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -KeyPath 'c:\users\username\documents\personal.key' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Key File and Uses NetworkAccount.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Uses NetworkAccount.
        .NOTES
            1. Currently all authentication combinations are supported except keyfile, masterkey password, and network authentication together.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Network')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $DatabasePath,

        [Parameter(Position = 2, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 2, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 3, ParameterSetName = 'Key')]
        [Parameter(Position = 3, ParameterSetName = 'Master')]
        [Parameter(Position = 3, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 4, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 4, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [Switch] $UseMasterKey,

        [Parameter(Position = 5)]
        [Switch] $Default,

        [Parameter(Position = 6)]
        [Switch] $PassThru
    )
    begin
    {
        if($PSCmdlet.ParameterSetName -eq 'Network' -and -not $UseNetworkAccount)
        {
            Write-Warning -Message '[BEGIN] Please Specify a valid Credential Combination.'
            Write-Warning -Message '[BEGIN] You can not have a only a database file with no authentication options.'
            Throw 'Please Specify a valid Credential Combination.'
        }
    }
    process
    {
        if (-not (Test-Path -Path $Global:KeePassConfigurationFile))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist. One will be generated now.'
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if($CheckIfProfileExists)
        {
            Write-Warning -Message ('[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName)
            Throw '[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName
        }
        else
        {
            try
            {
                if($Default)
                {
                    $defaultProfile = Get-KeePassDatabaseConfiguration -Default

                    if($defaultProfile)
                    {
                        throw ('{0} profile is already set to the default, if you would like to overwrite it as the default please use the Update-KeePassDatabaseConfiguration function and remove the default flag.' -f $defaultProfile.Name)
                    }
                }

                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($Global:KeePassConfigurationFile)
                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $DatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null

                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element', 'DatabasePath', '')
                $DatabasePathNode.InnerText = $DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null

                $KeyPathNode = $XML.CreateNode('element', 'KeyPath', '')
                $KeyPathNode.InnerText = $KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null

                $UseNetworkAccountNode = $XML.CreateNode('element', 'UseNetworkAccount', '')
                $UseNetworkAccountNode.InnerText = $UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null

                $UseMasterKeyNode = $XML.CreateNode('element', 'UseMasterKey', '')
                $UseMasterKeyNode.InnerText = $UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null

                $AuthenticationTypeNode = $XML.CreateNode('element', 'AuthenticationType', '')
                $AuthenticationTypeNode.InnerText = $PSCmdlet.ParameterSetName
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $DefaultNode = $XML.CreateNode('element', 'Default', '')
                $DefaultNode.InnerText = $Default
                $DatabaseProfile.AppendChild($DefaultNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').AppendChild($DatabaseProfile) | Out-Null

                $XML.Save($Global:KeePassConfigurationFile)

                $Script:KeePassProfileNames = (Get-KeePassDatabaseConfiguration).Name

                if($PassThru)
                {
                    Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
                }
            }
            catch
            {
                Write-Warning -Message ('[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ({0}) to the configuration file.' -f $DatabaseProfileName)
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}
