# Changelog

## v2.0.5.6

* Update-KeePassEntry no longer creates a new entry, Entry history is retained, UUID is never changed, All time modificiation fields are now updated when appropriate. 
  * [#127](https://github.com/PSKeePass/PoShKeePass/issues/127)
  * [#123](https://github.com/PSKeePass/PoShKeePass/issues/123)
  * [#120](https://github.com/PSKeePass/PoShKeePass/issues/120)
* Code clean up in the internal functions
  * Removed unecessary comments.
  * Simplified parameter attributes, and formatting.
  * Updated error handling to use write-error and simplified handling.
* Normalized repetative checks to their own `Test-X` functions and moved error\null handling inside.
  * Test-KPConnection - Checks to see if connection exists and and is open.
  * Test-KPPasswordValue - Correctly checks for supported types and moved error handling inside.
* Fixed Dev Tool AutoVersioning Script, now updates psd1 version again.
* Simplified `Import-KPLibrary` function.
* Updated `ConvertTo-KPPSObject` to be construct PSObject differently and gained 86% speed performance improvement.
* Created a `build.ps1` script to build the module for use and publishing to gallery
* Updated `New-KPConnection` to prompt for user MasterKey (keepass passsword) via console prompt `Read-host` instead of `$Host.ui.PromptForCredential()`, this is much faster than loading the gui.

## v2.0.4.5

* #135 - Restructured Module to a more modular structure. Single file per function, seperate root folders for exported functions vs internal functions, (functions, internal).
* Added global variable `$Global:KeePassConfigurationFile` with the path of the config file and updated all references to file.
* Updated formatting of readme and changelog to abide by md standards.

## v2.0.4.4

* Some Community PR here, great help thank you
* #53, #117 `-AsPSCredential` Support to `Get-KeePassEntry`
* `-Title` Parameter Added to `Get-KeePassEntry`
* General bug fixes #115, #116, #120, #123, #127
* `New-KeePassDatabase` function added

## v2.0.4.3

* [#133](https://github.com/PSKeePass/PoShKeePass/issues/133) Fixed

## v2.0.4.1

* [#132](https://github.com/PSKeePass/PoShKeePass/issues/132) Fixed - Windows Defender identifies PoshKeepass as trojan. Please see the issue for more details.

## v2.0.4.0

* #108 Fixed bug by capturing PSCredential to MasterKey variable.

## v2.0.3.9

1. #92 Added PowerShell Format XML File for creating PowerShell Object views.
2. #90 Updated default properties returned for KeePass Entries to Include the Notes Property. Did this via the new format XML file.
3. #67 Consolidated KeePass database connection and authentication functions. Thanks @Ninjigen for your help on this.
4. #67 Now supports authentication using all three methods as a combination: MasterKey, KeyFile, WindowsAccount. 
5. #100 Fixed bug when using the `-MasterKey` options on and of the functions. The proper variable is now removed.
6. #95 Added internal function `Restore-KPConfigurationFile`. This is implemented to restore your configuration file from a previous version of the module, when updating from PSGallery.
7. Moved exported functions to the Module Manifest.

## v2.0.3.1

### Issue #79 - Added support Icon Management

* Updated `New` and `Update` Entry and Group functions to support setting and updating Icon values.
* Update `ConvertTo-KPPSObject` to output the IconId.
* Added Pester Tests for adding and updating Icons.
* Update `Get-KPDynamicParameters` to support creating the Icon dynamic param from the `KeePassLib.PwIcon` Enum.

## v2.0.3.0

* Issue 68 - Update getting XML Configuration Document from `Get-Content` to creating a new `System.Xml.XmlDocument` object and using the `Load()` Method.

## v2.0.2.9

* Issue 66 - Updated `ReadString()` method calls to `ReadSafe()` method calls.
* Issue 71 - Updated to Use Proper String Interpolation.
* Issue 72 - Removed Commented out code.
* Issue 73 - Converted to Single Quotes Where Possible.
* Issue 74 - Formatted Code consistently.

## v2.0.2.6

* Updated `New-KeePassPassword` to output as `KeePassLib.Security.ProtectedString` - _This removed the plain text conversion to secure string.
* Updated All New/Update Entry Functions to support _SecureString_ or _ProtectedString_ for the KeePassPassword Parameter.

## v2.0.2.1

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
