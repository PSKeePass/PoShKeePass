$Content = Get-Content -Path "$PSScriptRoot\KeePassLib.dll" -Encoding Byte
$Base64 = [Convert]::ToBase64String($Content)
$Base64  | Out-File -FilePath "$PSScriptRoot\KeePassLib_Encoded.txt"
