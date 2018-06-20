function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        $Path = Resolve-Path ('{0}\..\bin\KeePassLib_2.34.dll' -f $PSScriptRoot)
        Add-Type -Path $Path.Path
    }
}
