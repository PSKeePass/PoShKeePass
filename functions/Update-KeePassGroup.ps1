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
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 1, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassParentGroupPath,

        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 3, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 4, Mandatory = $false)]
        [Switch] $Force
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 5 -MasterKeyPosition 6 -PwIconPosition 7
    }
    begin
    {
        Invoke-StandardBeginBlock -TestDBProfile -CreateKeePassConnection
    }
    process
    {
        if($KeePassParentGroupPath)
        {
            $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassParentGroupPath
            if(-not $KeePassParentGroup)
            {
                Write-Warning -Message ('[PROCESS] The Specified KeePass Parent Group Path ({0}) does not exist.' -f $KeePassGroupParentPath)
                Throw 'The Specified KeePass Parent Group Path ({0}) does not exist.' -f $KeePassGroupParentPath
            }
        }

        if($KeePassGroup.GetType().Name -eq 'PwGroup')
        {
            $KeePassGroupFullPath = '{0}' -f $KeePassGroup.GetFullPath('/', $true)
        }
        else
        {
            $KeePassGroupFullPath = '{0}/{1}' -f $KeePassGroup.FullPath, $KeePassGroup.Name
        }
        ## Confirm
        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroupFullPath))
        {
            $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupFullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime}

            if($KeePassGroupObject.Count -gt 1)
            {
                Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Update.'
                Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups' -f $KeePassGroupObject.Count)
                Throw 'Found more than one group with the same path, name and creation time.'
            }

            ## Set Default Icon if not specified.
            if(-not $IconName)
            {
                $IconName = $KeePassGroupObject.IconId
            }

            if($KeePassParentGroup)
            {

                Set-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -KeePassParentGroup $KeePassParentGroup -GroupName $GroupName -IconName $IconName -PassThru:$PassThru -Confirm:$false -Force
            }
            else
            {
                Set-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -GroupName $GroupName -IconName $IconName -PassThru:$PassThru -Confirm:$false -Force
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
