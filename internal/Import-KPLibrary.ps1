function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        Write-Debug -Message '[PROCESS] Checking if KeePassLib is already loaded.'
        $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()
        $KeePassAssembly = $LoadedAssemblies | Where-Object { $_.FullName -match "KeePassLib"}

        if($KeePassAssembly)
        {
            $KeePassAssemblyInfo = @{
                'Name'     = $KeePassAssembly.FullName.Replace(' ', '').Split(',')[0]
                'Version'  = $KeePassAssembly.FullName.Replace(' ', '').Split(',')[1].Split('=')[1]
                'Location' = $KeePassAssembly.Location
            }

            if($KeePassAssemblyInfo.Name -eq 'KeePassLib')
            {
                if($KeePassAssemblyInfo.Version -eq '2.30.0.15901')
                {
                    Write-Verbose -Message ('KeePassLib has already been loaded, from: {0}.' -f $KeePassAssemblyInfo.Location)
                    Write-Debug -Message ('KeePassLib Assembly Name: {0}, Version: {1}' -f $KeePassAssemblyInfo.Name, $KeePassAssemblyInfo.Version)
                    $KeePassAssemblyIsLoaded = $true
                }
                else
                {
                    Write-Debug -Message '[PROCESS] A KeePassLib Assembly is loaded but it does not match the required version: ''2.30.0.15901'''
                    Write-Debug -Message ('[PROCESS] Version Found: {0}' -f $KeePassAssemblyInfo.Version)
                    Write-Debug -Message '[PROCESS] Will continue to load the correct version.'
                }
            }
            else
            {
                Write-Debug -Message '[PROCESS] No Loaded Assembly found for KeePassLib. Will Continue to load the Assembly.'
            }
        }

        if(-not $KeePassAssemblyIsLoaded)
        {
            $Path = Resolve-Path ('{0}\..\bin\KeePassLib.dll' -f $PSScriptRoot)
            Add-Type -Path $Path.Path
        }
    }
}
