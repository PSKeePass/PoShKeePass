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
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 1)]
        [Switch] $NoRecycle,

        [Parameter(Position = 2)]
        [Switch] $Force,

        [Parameter(Position = 3, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        Remove-Variable -Name MasterKey -ea 0

        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        $EntryDisplayName = '{0}/{1}' -f $KPEntry.ParentGroup.GetFullPath('/', $true), $KPEntry.Strings.ReadSafe('Title')
        if($Force -or $PSCmdlet.ShouldProcess($EntryDisplayName))
        {
            [hashtable] $params = @{
                'KeePassConnection' = $KeePassConnectionObject;
                'KeePassEntry'      = $KPEntry;
                'Confirm'           = $false;
                'Force'             = $Force;
            }

            if($NoRecycle){ $params.NoRecycle = $NoRecycle }
            Remove-KPEntry @params
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
