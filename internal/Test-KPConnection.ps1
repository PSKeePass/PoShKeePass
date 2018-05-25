function Test-KPConnection
{
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [PSObject] $KeePassConnection
    )

    if($KeePassConnection.IsOpen)
    {
        $true
    }
    else
    {
        $false
        Write-Warning -Message 'The KeePass Connection Sepcified is not open or does not exist.'
        Write-Error -Message 'The KeePass Connection Sepcified is not open or does not exist.' -ea Stop
    }
}
