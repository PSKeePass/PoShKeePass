function ConvertTo-KPPSObject
{
    <#
        .SYNOPSIS
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.
        .DESCRIPTION
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.

            It will get the Protected Strings from the database like, Title,UserName,Password,URL,Notes.

            It currently returns Most frequently used data about an entry and excludes extensive metadata such as-
            Foreground Color, Icon, ect.
        .EXAMPLE
            PS> ConvertTo-KPPsObject -KeePassEntry $Entry

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .EXAMPLE
            PS> Get-KeePassEntry -KeePassonnection $DB -UserName "AUserName" | ConvertTo-KeePassPsObject

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .PARAMETER KeePassEntry
            This is the one or more KeePass Entries to be converted.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Entry')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Entry')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $KeePassEntry,

        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position = 1, ParameterSetName = 'Entry')]
        [switch] $WithCredential,

        [Parameter(Position = 2, ParameterSetName = 'Entry')]
        [switch] $AsPlainText,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName)]
        [string] $DatabaseProfileName
    )
    process
    {
        if($PSCmdlet.ParameterSetName -eq 'Entry')
        {
            foreach ($_keepassItem in $KeePassEntry)
            {
                if($WithCredential)
                {
                    try
                    {
                        $Credential = New-Object -TypeName PSCredential -ArgumentList @($_keepassItem.Strings.ReadSafe('UserName'), ($_keepassItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force -ea SilentlyContinue))
                    }
                    catch{}
                }

                if($AsPlainText)
                { $Password = $_keepassItem.Strings.ReadSafe('Password') }
                else
                { $Password = $_keepassItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force -ea SilentlyContinue }

                $KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
                        'Uuid'                    = $_keepassItem.Uuid;
                        'CreationTime'            = $_keepassItem.CreationTime;
                        'Expires'                 = $_keepassItem.Expires;
                        'ExpireTime'              = $_keepassItem.ExpiryTime;
                        'LastAccessTimeUtc'       = $_keepassItem.LastAccessTime;
                        'LastModificationTimeUtc' = $_keepassItem.LastModificationTime;
                        'LocationChanged'         = $_keepassItem.LocationChanged;
                        'Tags'                    = $_keepassItem.Tags;
                        'Touched'                 = $_keepassItem.Touched;
                        'UsageCount'              = $_keepassItem.UsageCount;
                        'ParentGroup'             = $_keepassItem.ParentGroup.Name;
                        'FullPath'                = $_keepassItem.ParentGroup.GetFullPath('/', $true);
                        'Title'                   = $_keepassItem.Strings.ReadSafe('Title');
                        'UserName'                = $_keepassItem.Strings.ReadSafe('UserName');
                        'Password'                = $Password
                        'URL'                     = $_keepassItem.Strings.ReadSafe('URL');
                        'Notes'                   = $_keepassItem.Strings.ReadSafe('Notes');
                        'IconId'                  = $_keepassItem.IconId;
                        'Credential'              = $Credential;
                        'DatabaseProfileName'     = $DatabaseProfileName;
                        'KPEntry'                 = $_keepassItem;
                    })

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Entry')

                $KeePassPsObject

                if($Password){ Remove-Variable -Name 'Password' }
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Group')
        {
            foreach ($_keepassItem in $KeePassGroup)
            {
                if($_keepassItem.ParentGroup.Name)
                { $FullPath = $_keepassItem.ParentGroup.GetFullPath('/', $true) }
                else
                { $FullPath = '' }

                $KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
                        'Uuid'                    = $_keepassItem.Uuid;
                        'Name'                    = $_keepassItem.Name;
                        'CreationTime'            = $_keepassItem.CreationTime;
                        'Expires'                 = $_keepassItem.Expires;
                        'ExpireTime'              = $_keepassItem.ExpiryTime;
                        'LastAccessTimeUtc'       = $_keepassItem.LastAccessTime;
                        'LastModificationTimeUtc' = $_keepassItem.LastModificationTime;
                        'LocationChanged'         = $_keepassItem.LocationChanged;
                        'Notes'                   = $_keepassItem.Notes;
                        'Touched'                 = $_keepassItem.Touched;
                        'UsageCount'              = $_keepassItem.UsageCount;
                        'ParentGroup'             = $_keepassItem.ParentGroup.Name;
                        'FullPath'                = $_keepassItem.GetFullPath('/', $true);
                        'Groups'                  = $_keepassItem.Groups;
                        'EntryCount'              = $_keepassItem.Entries.Count;
                        'IconId'                  = $_keepassItem.IconId;
                        'DatabaseProfileName'     = $DatabaseProfileName;
                        'KPGroup'                 = $_keepassItem;
                    })

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Group')
                $PSKeePassGroupDisplaySet = 'Name', 'EntryCount', 'FullPath', 'IconId'
                $PSKeePassGroupDefaultPropertySet = New-Object -TypeName System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [String[]] $PSKeePassGroupDisplaySet)
                $PSKeePassGroupStandardMembers = [System.Management.Automation.PSMemberInfo[]] @($PSKeePassGroupDefaultPropertySet)

                $KeePassPsObject | Add-Member MemberSet PSStandardMembers $PSKeePassGroupStandardMembers

                $KeePassPsObject
            }
        }
    }
    end
    {
        if($Credential){ Remove-Variable -Name 'Credential' }
    }
}
