function Test-KPPasswordValue
{
    param
    (
        [PSObject] $PassValue
    )
    if(-not $PassValue)
    {
        $true
    }
    elseif($PassValue.GetType().Name -eq 'SecureString')
    {
        $true
    }
    elseif($PassValue.GetType().Name -eq 'ProtectedString')
    {
        $true
    }
    else
    {
        $false
    }
}
