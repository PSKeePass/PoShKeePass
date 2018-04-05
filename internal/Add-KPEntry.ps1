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
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

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
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 8, Mandatory = $false)]
        [Switch] $PassThru
    )
    begin
    {

        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
        }

        try
        {
            $KeePassEntry = New-Object KeePassLib.PwEntry($true, $true) -ErrorAction Stop -ErrorVariable ErrorNewPwEntryObject
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpEntry Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
                Write-Warning -Message ('[BEGIN] {0}' -f $ErrorNewPwEntryObject.ErrorRecord.Message)
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
        if(-not (Test-KPPasswordValue $KeePassPassword))
        {
            Write-Warning -Message '[PROCESS] Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
            Write-Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
            Throw 'Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
        }

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
        else
        {
            ## get password based on default pattern
            $KeePassSecurePasswordString = New-KeePassPassword
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

        #Add to Group
        $KeePassGroup.AddEntry($KeePassEntry, $true)

        #save database
        $KeePassConnection.Save($null)

        if($PassThru)
        {
            $KeePassEntry
        }
    }
}
