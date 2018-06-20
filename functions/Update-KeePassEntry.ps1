function Update-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to update a KeePass Database Entry.
        .DESCRIPTION
            This function updates a KeePass Database Entry with basic properites available for specification.
        .PARAMETER KeePassEntry
            The KeePass Entry to be updated. Use the Get-KeePassEntry function to get this object.
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
            Specify to return the modified object.
        .PARAMETER Force
            Specify to Update the specified entry without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example updates a keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 7)]
        [Switch] $PassThru,

        [Parameter(Position = 8)]
        [Switch] $Force
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 9 -MasterKeyPosition 10 -PwIconPosition 11
    }
    begin
    {
    }
    process
    {
        Invoke-StandardBeginBlock -TestDBProfile -CreateKeePassConnection

        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        ## Set Default Icon if not specified.
        if(-not $IconName)
        {
            $IconName = $KPEntry.IconId
        }

        if($Force -or $PSCmdlet.ShouldProcess("Title: $($KPEntry.Strings.ReadSafe('Title')), `n`tUserName: $($KPEntry.Strings.ReadSafe('UserName')), `n`tGroupPath: $($KPEntry.ParentGroup.GetFullPath('/', $true))."))
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            Set-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KPEntry -Title $Title -UserName $UserName -KeePassPassword $KeePassPassword -Notes $Notes -URL $URL -KeePassGroup $KeePassGroup -IconName $IconName -PassThru:$PassThru -Force | ConvertTo-KPPSObject -DatabaseProfileName $DatabaseProfileName
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
