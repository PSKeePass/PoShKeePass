function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        $Path = Resolve-Path $Global:KeePassLibraryPath
        Add-Type -Path $Path.Path
    }
}
