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
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2)]
        [String] $Title,

        [Parameter(Position = 3)]
        [String] $UserName,

        [Parameter(Position = 4)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [String] $URL,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 8)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 9)]
        [Switch] $PassThru,

        [Parameter(Position = 10)]
        [Switch] $Force
    )
    process
    {
        if((Test-KPPasswordValue $KeePassPassword) -and (Test-KPConnection $KeePassConnection))
        {

            if($Force -or $PSCmdlet.ShouldProcess("Title: $($KeePassEntry.Strings.ReadSafe('Title')). `n`tUserName: $($KeePassEntry.Strings.ReadSafe('UserName')). `n`tGroup Path $($KeePassEntry.ParentGroup.GetFullPath('/', $true))"))
            {
                [KeePassLib.PwEntry] $OldEntry = $KeePassEntry.CloneDeep()

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

                if($IconName -and $IconName -ne $KeePassEntry.IconId)
                {
                    $KeePassEntry.IconId = $IconName
                }

                $KeePassEntry.History.Add($OldEntry)

                if($KeePassGroup)
                {
                    $OldKeePassGroup = $KeePassEntry.ParentGroup
                    ## Add to group and move
                    $KeePassGroup.AddEntry($KeePassEntry, $true, $true)
                    ## delete old entry
                    $null = $OldKeePassGroup.Entries.Remove($KeePassEntry)
                }

                ## Add History Entry
                $KeePassEntry.LastModificationTime = [DateTime]::UtcNow
                $KeePassEntry.LastAccessTime = [DateTime]::UtcNow

                ## Save for safety
                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $KeePassEntry
                }
            }
        }
    }
}
