function Remove-KPEntry
{
    <#
        .SYNOPSIS
            Remove a Specific KeePass Entry.
        .DESCRIPTION
            Remove a Specified KeePass Database Entry.
         .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KPConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to be deleted.
        .PARAMETER NoRecycle
            Specify this flag to Permanently delete an entry. (ei skip the recycle bin)
        .PARAMETER Force
            Specify this flag to forcefully delete an entry.
        .EXAMPLE
            PS> Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KeePassEntryObject

            This Will remove a keepass database entry and prompt for confirmation.
        .INPUTS
            Strings
            KeePassLib.PwDatabase
            KeePassLib.PwEntry
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = "High"
    )]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [Switch] $NoRecycle,

        [Parameter(
            Mandatory = $false,
            Position = 3
        )]
        [Switch] $Force
    )
    begin
    {

        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
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
        $EntryDisplayName = "$($KeePassEntry.ParentGroup.GetFullPath('/', $true))/$($KeePassEntry.Strings.ReadSafe('Title'))"
    }
    process
    {
        if($Force -or $PSCmdlet.ShouldProcess($($EntryDisplayName)))
        {
            if($RecycleBin -and -not $NoRecycle)
            {
                ## Make Copy of the group to be recycled.
                $DeletedKeePassEntry = $KeePassEntry.CloneDeep()
                ## Generate a new Uuid and update the copy fo the group
                $DeletedKeePassEntry.Uuid = (New-Object KeePassLib.PwUuid($true))
                ## Add the copy to the recycle bin, with take ownership set to true
                $RecycleBin.AddEntry($DeletedKeePassEntry, $true)
                ## Save for safety
                $KeePassConnection.Save($null)
                ## Delete Original Entry
                $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry) > $null
                ## Save again
                $KeePassConnection.Save($null)
                Write-Verbose -Message "[PROCESS] Group has been Recycled."
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue("Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.", "Do you want to continue to Permanently Delete this Entry: ($($EntryDisplayName))?"))
                {
                    ## Deletes the specified group
                    $IsRemoved = $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry)

                    if(-not $IsRemoved)
                    {
                        Write-Warning -Message "[PROCESS] Unknown Error has occured. Failed to Remove Entry ($($EntryDisplayName))"
                        Throw "Failed to Remove Entry $($EntryDisplayName)"
                    }
                    else
                    {
                        Write-Verbose -Message "[PROCESS] Entry ($($EntryDisplayName)) has been Removed."
                        $KeePassConnection.Save($null)
                    }
                }
            }
        }
    }
}
