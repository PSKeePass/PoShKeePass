function Add-KPGroup
{
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER PassThru
            Specify to return the new keepass group object.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullorEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 3)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 4)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message ('[BEGIN] {0}' -f $ErrorNewPwGroupObject.ErrorRecord.Message)
                Throw $_
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            $KeePassGroup.Name = $GroupName
            if($IconName -ne $KeePassGroup.IconId)
            {
                $KeePassGroup.IconId = $IconName
            }
            $KeePassParentGroup.AddGroup($KeePassGroup, $true)
            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassGroup
            }
        }
    }
}
