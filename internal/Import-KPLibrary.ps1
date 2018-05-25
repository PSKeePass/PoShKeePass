function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        $Path = Resolve-Path ('{0}\..\bin\KeePassLib.dll' -f $PSScriptRoot)
        Add-Type -Path $Path.Path
    }
}
