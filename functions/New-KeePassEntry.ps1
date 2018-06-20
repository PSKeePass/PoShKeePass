function New-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the newly created keepass database entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example creates a new keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 6)]
        [Switch] $PassThru
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 7 -MasterKeyPosition 8 -PwIconPosition 9
    }
    begin
    {
    }
    process
    {
        Invoke-StandardBeginBlock -TestDBProfile -CreateKeePassConnection
        if(-not $IconName){ $IconName = 'Key' }

        try
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $addKpEntrySplat = @{
                URL               = $URL
                UserName          = $UserName
                IconName          = $IconName
                KeePassGroup      = $KeePassGroup
                KeePassPassword   = $KeePassPassword
                PassThru          = $PassThru
                Title             = $Title
                KeePassConnection = $KeePassConnectionObject
                Notes             = $Notes
            }

            Add-KpEntry @addKpEntrySplat | ConvertTo-KPPSObject -DatabaseProfileName $DatabaseProfileName
        }
        catch
        { Throw $_ }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
