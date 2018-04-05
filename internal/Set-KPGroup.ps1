function Set-KPGroup
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
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER PassThru
            Specify to return the updated group object.
        .PARAMETER Force
            Specify to force updating the group.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2, Mandatory = $false)]
        [String] $GroupName,

        [Parameter(Position = 3, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 4, Mandatory = $false)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 5, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 6, Mandatory = $false)]
        [Switch] $Force
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }
    }
    process
    {
        if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
        {
            if($GroupName)
            {
                $KeePassGroup.Name = $GroupName
            }

            if($IconName -ne $KeePassGroup.IconId)
            {
                $KeePassGroup.IconId = $IconName
            }

            if($KeePassParentGroup)
            {
                if($KeePassGroup.ParentGroup.Uuid.CompareTo($KeePassParentGroup.Uuid) -ne 0 )
                {
                    $UpdatedKeePassGroup = $KeePassGroup.CloneDeep()
                    $UpdatedKeePassGroup.Uuid = New-Object KeePassLib.PwUuid($true)
                    $KeePassParentGroup.AddGroup($UpdatedKeePassGroup, $true, $true)
                    $KeePassConnection.Save($null)
                    $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                    $KeePassConnection.Save($null)
                    $KeePassGroup = $UpdatedKeePassGroup
                }
            }
            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassGroup
            }
        }
    }
}
