## Taken and Modified from DBATools
function Test-Bound
{
    <#
        .SYNOPSIS
            Helperfunction that tests, whether a parameter was bound.

        .DESCRIPTION
            Helperfunction that tests, whether a parameter was bound.

        .PARAMETER ParameterName
            The name(s) of the parameter that is tested for being bound.
            By default, the check is true when AT LEAST one was bound.

        .PARAMETER Not
            Reverses the result. Returns true if NOT bound and false if bound.

        .PARAMETER And
            All specified parameters must be present, rather than at least one of them.

        .PARAMETER BoundParameters
            The hashtable of bound parameters. Is automatically inherited from the calling function via default value. Needs not be bound explicitly.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [string[]] $ParameterName,

        [Alias('Reverse')]
        [switch] $Not,

        [switch] $And,

        [object] $BoundParameters = (Get-PSCallStack)[0].InvocationInfo.BoundParameters
    )
    process
    {
        if($And)
        {
            $test = $true
        }
        else
        {
            $test = $false
        }

        foreach($name in $ParameterName)
        {
            if($And)
            {
                if(-not $BoundParameters.ContainsKey($name))
                {
                    $test = $false
                }
            }
            else
            {
                if($BoundParameters.ContainsKey($name))
                {
                    $test = $true
                }
            }
        }

        return ((-not $Not) -eq $test)
    }
}