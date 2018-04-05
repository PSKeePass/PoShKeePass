function Remove-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Entry.
        .DESCRIPTION
            This function removed a KeePass Database Entry.
        .PARAMETER KeePassEntry
            The KeePass Entry to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the entry and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassEntry -KeePassEntry $KeePassEntryObject

            This example removed the specified kee pass entry.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

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
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }
        $EntryDisplayName = '{0}/{1}' -f $KPEntry.ParentGroup.GetFullPath('/', $true), $KPEntry.Strings.ReadSafe('Title')
        if($Force -or $PSCmdlet.ShouldProcess($EntryDisplayName))
        {
            if($NoRecycle)
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Do you want to continue to Permanently Delete this Entry: $EntryDisplayName)?"))
                {
                    Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KPEntry -NoRecycle -Confirm:$false -Force
                }
            }
            else
            {
                Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KPEntry -Confirm:$false -Force
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
