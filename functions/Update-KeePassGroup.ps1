function Update-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to update a KeePass Database Group.
        .DESCRIPTION
            This function updates a KeePass Database Group.
        .PARAMETER KeePassGroup
            The KeePass Group to be updated. Use the Get-KeePassGroup function to get this object.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish move the specified group to a different parent group.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER GroupName
            Specify the GroupName to change the specified group to.
        .PARAMETER PassThru
            Specify to return the updated keepass group object.
        .PARAMETER Force
            Specify to Update the specified group without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> Update-KeePassGroup -DatabaseProfileName TEST -KeePassGroup $KeePassGroupObject -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves the specified KeePassGroup to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves group specified via the pipeline to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -GroupName 'DevGroup'

            This Example renames the group specified via the pipeline to 'DevGroup'
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
        [PSObject] $KeePassGroup,

        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassParentGroupPath,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 3)]
        [switch] $Expires,

        [Parameter(Position = 4)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 5, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 7)]
        [Switch] $PassThru,

        [Parameter(Position = 8)]
        [Switch] $Force
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        Remove-Variable -Name MasterKey -ea 0

        if($KeePassParentGroupPath -and $KeePassParentGroupPath -ne $KeePassGroup.FullPath)
        {
            $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassParentGroupPath -Stop
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroup.FullPath))
        {
            $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroup.FullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime }

            if($KeePassGroupObject.Count -gt 1)
            {
                Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Update.'
                Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups' -f $KeePassGroupObject.Count)
                Throw 'Found more than one group with the same path, name and creation time.'
            }

            $setKPGroupSplat = @{
                KeePassConnection = $KeePassConnectionObject
                KeePassGroup      = $KeePassGroupObject
                PassThru          = $PassThru
                Force             = $true
                GroupName         = $GroupName
                Confirm           = $false
                Notes             = $Notes
            }

            if($IconName){ $setKPGroupSplat.IconName = $IconName }
            if($KeePassParentGroup){ $setKPGroupSplat.KeePassParentGroup = $KeePassParentGroup }
            if(Test-Bound -ParameterName 'Expires'){ $setKPGroupSplat.Expires = $Expires }
            if($ExpiryTime){ $setKPGroupSplat.ExpiryTime = $ExpiryTime }

            Set-KPGroup @setKPGroupSplat | ConvertTo-KpPsObject -DatabaseProfileName $DatabaseProfileName
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
