function New-KeePassDatabase
{
    <#
        .SYNOPSIS
            Function to create a keepass database.
        .DESCRIPTION
            This function creates a new keepass database
        .PARAMETER DatabasePath
            Path to the Keepass database (.kdbx file)
        .PARAMETER KeyPath
            Not yet implemented
        .PARAMETER UseNetworkAccount
            Specify of you want the database to use windows authentication
        .PARAMETER MasterKey
            The masterkey that provides access to the database
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabasePath,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 2, ParameterSetName = 'Key')]
        [Parameter(Position = 2, ParameterSetName = 'Master')]
        [Parameter(Position = 2, Mandatory = $true, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 3, Mandatory = $true, ParameterSetName = 'Master')]
        [Parameter(Position = 3, Mandatory = $true, ParameterSetName = 'KeyAndMaster')]
        [PSCredential] $MasterKey
    )

    begin
    {
        if($KeyPath)
        { throw "KeyPath is not implemented yet" }
    }
    process
    {
        try
        {
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }
        catch
        {
            Import-KPLibrary
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }

        $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

        if($MasterKey)
        {
            $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($MasterKey.GetNetworkCredential().Password)
            $CompositeKey.AddUserKey($KcpPassword)
        }

        if($UseNetworkAccount)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
        }

        $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
        $IOInfo.Path = $DatabasePath

        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

        $DatabaseObject.New($IOInfo, $CompositeKey) | Out-Null
        $DatabaseObject.Save($IStatusLogger)
    }
}
