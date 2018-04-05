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
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Entry')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $KeePassEntry,
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup
    )
    process
    {
        if($PSCmdlet.ParameterSetName -eq 'Entry')
        {
            foreach ($_keepassItem in $KeePassEntry)
            {
                ## Build Object
                $KeePassPsObject = New-Object -TypeName PSObject
                $KeePassPsObject | Add-Member -Name 'Uuid' -MemberType NoteProperty -Value $_keepassItem.Uuid
                $KeePassPsObject | Add-Member -Name 'CreationTime' -MemberType NoteProperty -Value $_keepassItem.CreationTime
                $KeePassPsObject | Add-Member -Name 'Expires' -MemberType NoteProperty -Value $_keepassItem.Expires
                $KeePassPsObject | Add-Member -Name 'ExpireTime' -MemberType NoteProperty -Value $_keepassItem.ExpiryTime
                $KeePassPsObject | Add-Member -Name 'LastAccessTime' -MemberType NoteProperty -Value $_keepassItem.LastAccessTime
                $KeePassPsObject | Add-Member -Name 'LastModificationTime' -MemberType NoteProperty -Value $_keepassItem.LastModificationTime
                $KeePassPsObject | Add-Member -Name 'LocationChanged' -MemberType NoteProperty -Value $_keepassItem.LocationChanged
                $KeePassPsObject | Add-Member -Name 'Tags' -MemberType NoteProperty -Value $_keepassItem.Tags
                $KeePassPsObject | Add-Member -Name 'Touched' -MemberType NoteProperty -Value $_keepassItem.Touched
                $KeePassPsObject | Add-Member -Name 'UsageCount' -MemberType NoteProperty -Value $_keepassItem.UsageCount
                $KeePassPsObject | Add-Member -Name 'ParentGroup' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.Name
                $KeePassPsObject | Add-Member -Name 'FullPath' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.GetFullPath('/', $true)
                $KeePassPsObject | Add-Member -Name 'Title' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('Title')
                $KeePassPsObject | Add-Member -Name 'UserName' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('UserName')
                $KeePassPsObject | Add-Member -Name 'Password' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('Password')
                $KeePassPsObject | Add-Member -Name 'URL' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('URL')
                $KeePassPsObject | Add-Member -Name 'Notes' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('Notes')
                $KeePassPsObject | Add-Member -Name 'IconId' -MemberType NoteProperty -Value $_keepassItem.IconId

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Entry')

                ## Return Object
                $KeePassPsObject
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Group')
        {
            foreach ($_keepassItem in $KeePassGroup)
            {
                if($_keepassItem.ParentGroup.Name)
                {
                    $FullPath = $_keepassItem.ParentGroup.GetFullPath('/', $true)
                }
                else
                {
                    $FullPath = ''
                }
                $KeePassPsObject = New-Object -TypeName PSObject
                $KeePassPsObject | Add-Member -Name 'Uuid' -MemberType NoteProperty -Value $_keepassItem.Uuid
                $KeePassPsObject | Add-Member -Name 'Name' -MemberType NoteProperty -Value $_keepassItem.Name
                $KeePassPsObject | Add-Member -Name 'CreationTime' -MemberType NoteProperty -Value $_keepassItem.CreationTime
                $KeePassPsObject | Add-Member -Name 'Expires' -MemberType NoteProperty -Value $_keepassItem.Expires
                $KeePassPsObject | Add-Member -Name 'ExpireTime' -MemberType NoteProperty -Value $_keepassItem.ExpiryTime
                $KeePassPsObject | Add-Member -Name 'LastAccessTime' -MemberType NoteProperty -Value $_keepassItem.LastAccessTime
                $KeePassPsObject | Add-Member -Name 'LastModificationTime' -MemberType NoteProperty -Value $_keepassItem.LastModificationTime
                $KeePassPsObject | Add-Member -Name 'LocationChanged' -MemberType NoteProperty -Value $_keepassItem.LocationChanged
                $KeePassPsObject | Add-Member -Name 'Touched' -MemberType NoteProperty -Value $_keepassItem.Touched
                $KeePassPsObject | Add-Member -Name 'UsageCount' -MemberType NoteProperty -Value $_keepassItem.UsageCount
                $KeePassPsObject | Add-Member -Name 'ParentGroup' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.Name
                $KeePassPsObject | Add-Member -Name 'FullPath' -MemberType NoteProperty -Value $FullPath
                $KeePassPsObject | Add-Member -Name 'Groups' -MemberType NoteProperty -Value $_keepassItem.Groups
                $KeePassPsObject | Add-Member -Name 'EntryCount' -MemberType NoteProperty -Value $_keepassItem.Entries.Count
                $KeePassPsObject | Add-Member -Name 'IconId' -MemberType NoteProperty -Value $_keepassItem.IconId

                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Group')
                $PSKeePassGroupDisplaySet = 'Name', 'EntryCount', 'FullPath', 'IconId'
                $PSKeePassGroupDefaultPropertySet = New-Object -TypeName System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [String[]] $PSKeePassGroupDisplaySet)
                $PSKeePassGroupStandardMembers = [System.Management.Automation.PSMemberInfo[]] @($PSKeePassGroupDefaultPropertySet)

                $KeePassPsObject | Add-Member MemberSet PSStandardMembers $PSKeePassGroupStandardMembers

                $KeePassPsObject
            }
        }
    }
}
