function Get-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Funciton gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -AsPlainText

            This Example will return all groups in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -KeePassGroupPath 'General' -AsPlainText

            This Example will return all groups in plain text format from the General folder of the keepass database with the profile name TEST.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupPath,

        [Parameter(Position = 1, Mandatory = $false)]
        [Switch] $AsPlainText
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 2 -MasterKeyPosition 3
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        if($KeePassGroupPath)
        {
            ## Get All entries in the specified group
            $ResultEntries = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupPath
        }
        else
        {
            ## Get all entries in all groups.
            $ResultEntries = Get-KPGroup -KeePassConnection $KeePassConnectionObject
        }

        ## return results in plain text or not.
        if($AsPlainText)
        {
            $ResultEntries | ConvertTo-KpPsObject
        }
        else
        {
            $ResultEntries
        }
    }
    end
    {
        ## Clean up database connection
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
