function Get-KPGroup
{
    <#
        .SYNOPSIS
            Gets a KeePass Group Object.
        .DESCRIPTION
            Gets a KeePass Group Object. Type: KeePassLib.PwGroup
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -FullPath 'full/KPDatabase/pathtoGroup'

            This Example will return a KeePassLib.PwGroup array Object with the full group path specified.
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -GroupName 'Test Group'

            This Example will return a KeePassLib.PwGroup array Object with the groups that have the specified name.
        .PARAMETER KeePassConnection
            Specify the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER FullPath
            Specify the FullPath of a Group or Groups in a KPDB
        .PARAMETER GroupName
            Specify the GroupName of a Group or Groups in a KPDB.
        .PARAMETER KeePassUuid
            Specify the Uuid of the Group.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwGroup')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Full')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Partial')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Full')]
        [ValidateNotNullOrEmpty()]
        [String] $FullPath,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Partial')]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup[]] $KeePassOutGroups = $null
            [KeePassLib.PwGroup[]] $KeePassGroups = $KeePassConnection.RootGroup
            $KeePassGroups += $KeePassConnection.RootGroup.GetFlatGroupList()
        }
        catch
        {
            Write-Warning -Message 'An error occured while getting a KeePassLib.PwGroup Object.'
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if ($PSCmdlet.ParameterSetName -eq 'Full')
            {
                foreach($_keepassGroup in $KeePassGroups)
                {
                    if($_keepassGroup.GetFullPath('/', $true).ToLower().Equals($FullPath.ToLower()))
                    {
                        $_keepassGroup
                    }
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Partial')
            {
                foreach($_keepassGroup in $KeePassGroups)
                {
                    if($_keepassGroup.Name.ToLower().Equals($GroupName.ToLower()))
                    {
                        $_keepassGroup
                    }
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'None')
            {
                $KeePassGroups
            }
        }
    }
}
