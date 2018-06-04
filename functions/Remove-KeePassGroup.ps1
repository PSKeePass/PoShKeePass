function Remove-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Group.
        .DESCRIPTION
            This function removed a KeePass Database Group.
        .PARAMETER KeePassGroup
            The KeePass Group to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the Group and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the Group.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassGroup -KeePassGroup $KeePassGroupObject

            This example removed the specified keepass Group.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 1, Mandatory = $false)]
        [Switch] $NoRecycle,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $Force
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 3 -MasterKeyPosition 4
    }
    begin
    {
        Invoke-StandardBeginBlock -TestDBProfile -CreateKeePassConnection
    }
    process
    {
        if($KeePassGroup.GetType().Name -eq 'PwGroup')
        {
            $KeePassGroupFullPath = '{0}' -f $KeePassGroup.GetFullPath('/', $true)
        }
        else
        {
            $KeePassGroupFullPath = '{0}/{1}' -f $KeePassGroup.FullPath, $KeePassGroup.Name
        }
        $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupFullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime}

        if(-not $KeePassGroupObject)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Group does not exist.'
            Throw 'The Specified KeePass Group does not exist.'
        }

        if($KeePassGroupObject.Count -gt 1)
        {
            Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Removal.'
            Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups.' -f $KeePassGroupObject.Count)
            Throw 'Found more than one group with the same path, name and creation time. Stoping Removal.'
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroupFullPath))
        {
            if(-not $NoRecycle)
            {
                Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -Confirm:$false -Force
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Remove this Group permanetly: $KeePassGroupFullPath?"))
                {
                    Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -NoRecycle:$NoRecycle -Confirm:$false -Force
                }
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
