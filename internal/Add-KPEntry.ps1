function Add-KPEntry
{
    <#
        .SYNOPSIS
            This Function will add a new entry to a KeePass Database Group.
        .DESCRIPTION
            This Function will add a new entry to a KeePass Database Group.

            Currently This function supportes the basic fields for creating a new KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            This is the KeePass GroupObject to add the new Entry to.
        .PARAMETER Title
            This is the Title of the New KeePass Entry.
        .PARAMETER UserName
            This is the UserName of the New KeePass Entry.
        .PARAMETER KeePassPassword
            This is the Password of the New KeePass Entry.
        .PARAMETER Notes
            This is the Notes of the New KeePass Entry.
        .PARAMETER URL
            This is the URL of the New KeePass Entry.
        .PARAMETER PassThru
            Returns the New KeePass Entry after creation.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

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
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 8)]
        [bool] $Expires,

        [Parameter(Position = 9)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 10)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwEntry] $KeePassEntry = New-Object KeePassLib.PwEntry($true, $true) -ea Stop
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if((Test-KPPasswordValue $KeePassPassword) -and (Test-KPConnection $KeePassConnection))
        {
            if($Title)
            {
                [KeePassLib.Security.ProtectedString] $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                $KeePassEntry.Strings.Set('Title', $SecureTitle)
            }

            if($UserName)
            {
                [KeePassLib.Security.ProtectedString] $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                $KeePassEntry.Strings.Set('UserName', $SecureUser)
            }

            if($KeePassPassword)
            {
                if($KeePassPassword.GetType().Name -eq 'SecureString')
                {
                    [KeePassLib.Security.ProtectedString] $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                    $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                }
                elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                {
                    $KeePassSecurePasswordString = $KeePassPassword
                }
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }
            else
            {
                ## get password based on default pattern
                $KeePassSecurePasswordString = New-KeePassPassword
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }

            if($Notes)
            {
                [KeePassLib.Security.ProtectedString] $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                $KeePassEntry.Strings.Set('Notes', $SecureNotes)
            }

            if($URL)
            {
                [KeePassLib.Security.ProtectedString] $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                $KeePassEntry.Strings.Set('URL', $SecureURL)
            }

            if($IconName -and $IconName -ne $KeePassEntry.IconId)
            {
                $KeePassEntry.IconId = $IconName
            }

            if(Test-Bound -ParameterName 'Expires')
            {
                $KeePassEntry.Expires = $Expires
            }

            if($ExpiryTime)
            {
                $KeePassEntry.ExpiryTime = $ExpiryTime.ToUniversalTime()
            }

            $KeePassGroup.AddEntry($KeePassEntry, $true)

            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassEntry
            }
        }
    }
}
