function Invoke-StandardBeginBlock
{
    [CmdletBinding()]
    param
    (
        [switch] $TestDBProfile,

        [switch] $CreateKeePassConnection
    )
    begin
    {
        if($TestDBProfile)
        {
            $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
            if(-not $DatabaseProfileList)
            {
                Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
                Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
                Throw 'There are Currently No Database Configuration Profiles.'
            }
        }
    }
    process
    {
        ## Add Dynamic Parameters
        $psbound = Get-Variable -Name 'PSBoundParameters' -Scope 1
        $c = 0;
        $values = @($psbound.Value.Values)
        @($psbound.Value.Keys) | ForEach-Object {

            if(-not (Get-Variable -Name $_ -Scope 1 -ea 0))
            {
                $null = New-Variable -Name $_ -Value $values[$c] -Scope 1 -ea 0 -ev errorNewVar
                if($errorNewVar)
                {
                    $null = Set-Variable -Name $_ -Value $values[$c] -Scope 1
                }
            }

            $c++;
        }

        if($CreateKeePassConnection)
        {
            New-Variable -Scope 1 -Name 'KeePassConnectionObject' -Value (New-KPConnection -DatabaseProfileName (Get-Variable -Name 'DatabaseProfileName' -Scope 1 -ea 0).Value -MasterKey (Get-Variable -Name 'MasterKey' -Scope 1 -ea 0).Value)
        }

        ## remove any sensitive data
        Remove-Variable -Name MasterKey -Scope 1 -ea 0
    }
}