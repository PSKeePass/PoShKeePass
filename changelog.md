## Changelog PSKeePass v2.0.2.1

## Added Dynamic Parameter MasterKey
Added optional Parameter `-MasterKey` to core functions.

This parameter was added to allow for easier scripting with databases that use a masterkey password.

Previously if a masterkey password was used the updated functions would prompt the user of the masterkey after the funciton was called. This is still the behaviour if the masterkey is required but not specified.

Functions Updated:

1. `New-KeePassEntry`
2. `New-KeePassGroup`
3. `Get-KeePassEntry`
4. `Get-KeePassGroup`
5. `Update-KeePassEntry`
6. `Update-KeePassGroup`
7. `Remove-KeePassEntry`
8. `Remove-KeePassGroup`

## Simplfied Dynamic Parameters
Internally created a function that builds the commonly used Dynamic Parameters.

`Get-KPDynamicParameter`

## Simplfied Building an Automatic Database Connection 
Internally created a function that builds the Database connection based off of the Database Configuration Profile Specified.

`Invoke-KPConnection`
