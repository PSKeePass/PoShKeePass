## Changelog PoShKeePass v2.0.3.9

1. #92 Added PowerShell Format XML File for creating PowerShell Object views.
2. #90 Updated default properties returned for KeePass Entries to Include the Notes Property. Did this via the new format XML file.
3. #67 Consolidated KeePass database connection and authentication functions. Thanks @Ninjigen for your help on this.
4. #67 Now supports authentication using all three methods as a combination: MasterKey, KeyFile, WindowsAccount. 
5. #100 Fixed bug when using the `-MasterKey` options on and of the functions. The proper variable is now removed.
6. #95 Added internal function `Restore-KPConfigurationFile`. This is implemented to restore your configuration file from a previous version of the module, when updating from PSGallery.
7. Moved exported functions to the Module Manifest.

## Changelog PoShKeePass v2.0.3.1

### Issue #79 - Added support Icon Management
* Updated `New` and `Update` Entry and Group functions to support setting and
updating Icon values.
* Update `ConvertTo-KPPSObject` to output the IconId.
* Added Pester Tests for adding and updating Icons.
* Update `Get-KPDynamicParameters` to support creating the Icon dynamic
param from the `KeePassLib.PwIcon` Enum.

## Changelog PoShKeePass v2.0.3.0
* Issue 68 - Update getting XML Configuration Document from `Get-Content` to creating a new `System.Xml.XmlDocument` object and using the `Load()` Method.

## Changelog PoShKeePass v2.0.2.9
* Issue 66 - Updated `ReadString()` method calls to `ReadSafe()` method calls.
* Issue 71 - Updated to Use Proper String Interpolation.
* Issue 72 - Removed Commented out code.
* Issue 73 - Converted to Single Quotes Where Possible.
* Issue 74 - Formatted Code consistently.

## ChangeLog PoShKeePass v2.0.2.6

* Updated `New-KeePassPassword` to output as `KeePassLib.Security.ProtectedString` - _This removed the plain text
conversion to secure string._
* Updated All New/Update Entry Functions to support _SecureString_ or _ProtectedString_ for the KeePassPassword Parameter.

## Changelog PoShKeePass v2.0.2.1

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
