function Set-KPEntry
{
    <#
        .SYNOPSIS
            This Function will update a entry.
        .DESCRIPTION
            This Function will update a entry.

            Currently This function supportes the basic fields for a KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to update/set atrributes.
        .PARAMETER KeePassGroup
            Specifiy this if you want Move the KeePassEntry to another Group
        .PARAMETER Title
            This is the Title to update/set.
        .PARAMETER UserName
            This is the UserName to update/set.
        .PARAMETER KeePassPassword
            This is the Password to update/set.
        .PARAMETER Notes
            This is the Notes to update/set.
        .PARAMETER URL
            This is the URL to update/set.
        .PARAMETER PassThru
            Returns the updated KeePass Entry after updating.
        .PARAMETER Force
            Specify to force updating the KeePass Entry.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2, Mandatory = $false)]
        [String] $Title,

        [Parameter(Position = 3, Mandatory = $false)]
        [String] $UserName,

        [Parameter(Position = 4, Mandatory = $false)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5, Mandatory = $false)]
        [String] $Notes,

        [Parameter(Position = 6, Mandatory = $false)]
        [String] $URL,

        [Parameter(Position = 7, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 8, Mandatory = $false)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 9, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 10, Mandatory = $false)]
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
        if(-not (Test-KPPasswordValue $KeePassPassword))
        {
            Write-Warning -Message '[PROCESS] Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
            Write-Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
            Throw 'Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
        }

        ## Confirm or Force
        if($Force -or $PSCmdlet.ShouldProcess("Title: $($KeePassEntry.Strings.ReadSafe('Title')). `n`tUserName: $($KeePassEntry.Strings.ReadSafe('UserName')). `n`tGroup Path $($KeePassEntry.ParentGroup.GetFullPath('/', $true))"))
        {
            if($Title)
            {
                $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                $KeePassEntry.Strings.Set('Title', $SecureTitle)
            }

            if($UserName)
            {
                $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                $KeePassEntry.Strings.Set('UserName', $SecureUser)
            }

            if($KeePassPassword)
            {
                if($KeePassPassword.GetType().Name -eq 'SecureString')
                {
                    $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                    $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                }
                elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                {
                    $KeePassSecurePasswordString = $KeePassPassword
                }
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }

            if($Notes)
            {
                $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                $KeePassEntry.Strings.Set('Notes', $SecureNotes)
            }

            if($URL)
            {
                $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                $KeePassEntry.Strings.Set('URL', $SecureURL)
            }

            if($IconName)
            {
                if($IconName -ne $KeePassEntry.IconId)
                {
                    $KeePassEntry.IconId = $IconName
                }
            }

            ## If you are moving the entry to another group then take these actions.
            if($KeePassGroup)
            {
                ## Make Full Copy of Entry
                $NewKeePassEntry = $KeePassEntry.CloneDeep()
                ## Assign New Uuid to CloneDeep
                $NewKeePassEntry.Uuid = New-Object KeePassLib.PwUuid($true)
                ## Add Clone to Specified group
                $KeePassGroup.AddEntry($NewKeePassEntry, $true)
                ## Save for safety
                $KeePassConnection.Save($null)
                ## Delete previous entry
                ## Hide output
                $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry) > $null

                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $NewKeePassEntry
                }
            }

            ## user "colaloc" added this line. comment: we must change LastModificationTime to prevent synchronization problems
            $KeePassEntry.LastModificationTime = Get-Date
            ## user "colaloc" added this line. comment: any changes must be saved!
            $KeePassConnection.Save($null)
        }
    }
}
