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
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassGroupPath,

        [Parameter(Position = 1)]
        [Switch] $AsPlainText,

        [Parameter(Position = 2, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
        if($AsPlainText)
        { Write-Warning -Message 'The -AsPlainText switch parameter is deprecated and will be removed by end of year 2018!' }
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        Remove-Variable -Name MasterKey -ea 0

        [hashtable] $getKpGroupSplat = @{
            'KeePassConnection' = $KeePassConnectionObject
        }

        if($KeePassGroupPath)
        { $getKpGroupSplat.FullPath = $KeePassGroupPath }

        Get-KPGroup @getKpGroupSplat | ConvertTo-KpPsObject -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
