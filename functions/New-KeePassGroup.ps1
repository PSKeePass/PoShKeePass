function New-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER KeePassGroupName
            Specify the Name of the new KeePass Group.
        .PARAMETER PassThru
            Specify to return the new group object.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .EXAMPLE
            PS> New-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts' -KeePassGroupName 'TestGroup'

            This Example Creates a Group Called 'TestGroup' in the Group Path 'General/TestAccounts'
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupParentPath,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupName,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $PassThru
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 3 -MasterKeyPosition 4 -PwIconPosition 5
    }
    begin
    {
    }
    process
    {
        Invoke-StandardBeginBlock -TestDBProfile -CreateKeePassConnection

        ## Get the keepass group
        $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupParentPath -Stop

        ## Set Default Icon if not specified.
        if(-not $IconName)
        {
            $IconName = 'Folder'
        }
        ## Add the KeePass Group
        Add-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassParentGroup $KeePassParentGroup -GroupName $KeePassGroupName -IconName $IconName -PassThru:$PassThru
    }
    end
    {
        ## Clean up keepass database connection
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
