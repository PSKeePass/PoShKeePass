function Test-KPPasswordValue
{
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [PSObject] $KeePassPassword
    )

    if(-not $KeePassPassword)
    {
        $true
    }
    elseif($KeePassPassword.GetType().Name -eq 'SecureString')
    {
        $true
    }
    elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
    {
        $true
    }
    else
    {
        $false
        Write-Warning -Message '[PROCESS] Please provide a KeePassPassword of Type SecureString or KeePassLib.Security.ProtectedString.'
        Write-Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
        Write-Error -Message 'Please provide a KeePassPassword of Type SecureString or KeePassLib.Security.ProtectedString.' -ea Stop
    }
}
