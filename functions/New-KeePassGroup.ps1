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
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassGroupParentPath,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupName,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName = 'Folder',

        [Parameter(Position = 3)]
        [switch] $Expires,

        [Parameter(Position = 4)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 5, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 7)]
        [Switch] $PassThru
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        Remove-Variable -Name MasterKey -ea 0

        $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupParentPath -Stop

        $addKPGroupSplat = @{
            KeePassConnection  = $KeePassConnectionObject
            GroupName          = $KeePassGroupName
            IconName           = $IconName
            PassThru           = $PassThru
            KeePassParentGroup = $KeePassParentGroup
        }

        if(Test-Bound -ParameterName 'Expires'){ $addKPGroupSplat.Expires = $Expires }
        if($ExpiryTime){ $addKPGroupSplat.ExpiryTime = $ExpiryTime }

        Add-KPGroup @addKPGroupSplat | ConvertTo-KpPsObject -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
