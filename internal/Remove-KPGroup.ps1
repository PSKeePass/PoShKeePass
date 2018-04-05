function Remove-KPGroup
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Group
        .DESCRIPTION
            Function to remove a specified KeePass Group.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            Specify the Group to be removed.
        .PARAMETER NoRecycle
            Specify if you do not want the group to go to the Recycle Bin.
        .PARAMETER Force
            Specify to forcefully remove a group.
        .EXAMPLE
            PS> Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject

            Removes the specified account. Prompts before deletion and will put to recyclebin if there is one.
        .INPUTS
            KeePassLib.PwDatabase
            KeePassLib.PwGroup
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3, Mandatory = $false)]
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

        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }
    }
    process
    {
        if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
        {
            if($RecycleBin -and -not $NoRecycle)
            {
                ## Make Copy of the group to be recycled.
                $DeletedKeePassGroup = $KeePassGroup.CloneDeep()
                ## Generate a new Uuid and update the copy fo the group
                $DeletedKeePassGroup.Uuid = (New-Object KeePassLib.PwUuid($true))
                ## Add the copy to the recycle bin, with take ownership set to true
                $RecycleBin.AddGroup($DeletedKeePassGroup, $true, $true)
                $KeePassConnection.Save($null)
                $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                $KeePassConnection.Save($null)
                Write-Verbose -Message '[PROCESS] Group has been Recycled.'
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Do you want to continue to Permanently Delete this Group: ($($KeePassGroup.GetFullPath('/', $true)))?"))
                {
                    ## Deletes the specified group
                    $IsRemoved = $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup)
                    if(-not $IsRemoved)
                    {
                        Write-Warning -Message ('[PROCESS] Unknown Error has occured. Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true))
                        Throw 'Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true)
                    }
                    else
                    {
                        Write-Verbose -Message ('[PROCESS] Group ({0}) has been Removed.' -f $KeePassGroup.GetFullPath('/', $true))
                        $KeePassConnection.Save($null)
                    }
                }
            }
        }
    }
}
