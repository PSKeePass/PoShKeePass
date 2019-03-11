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
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
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
        [bool] $Expires,

        [Parameter(Position = 5)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 6)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ea Stop
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            $KeePassGroup.Name = $GroupName

            if($IconName -and $IconName -ne $KeePassGroup.IconId)
            {
                $KeePassGroup.IconId = $IconName
            }

            if(Test-Bound -ParameterName 'Expires')
            {
                $KeePassGroup.Expires = $Expires
            }

            if($ExpiryTime)
            {
                $KeePassGroup.ExpiryTime = $ExpiryTime.ToUniversalTime()
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
