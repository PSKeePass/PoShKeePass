# Changelog

## v.2.1.3.0

* Added [#160](https://github.com/PSKeePass/PoShKeePass/issues/160) - Default Database Configuration Profile.
  * When set, the `-DatabaseProfileName` parameter is optional, and if not passed it will grab the default profile from the config.
  * To Set it up on an existing profile simply use the update command:

  ```powershell
    Update-KeePassDatabaseConfigurationProfile -DatabaseProfileName 'name' -Default
  ```

  * To Create a new profile as default use the new command:

  ```powershell
    New-KeePassDatabaseConfigurationProfile -DatabaseProfileName 'name' -Default -DatabasePath '' other options
  ```

  * This allows for calls to the main module functions without the `-DatabaseProfileName` parameter such as:

  ```powershell
    Get-KeePassEntry -UserName 'aUser'
  ```

## v.2.1.2.8

* Added - [#84](https://github.com/PSKeePass/PoShKeePass/issues/84) - Manage Notes properties on KPGroup Objects.

* v.2.1.2.6 - Added - [#158](https://github.com/PSKeePass/PoShKeePass/issues/158) - Added Update-KeePassDatabaseConfiguration function and tests.

* v.2.1.2.5 - Fix - [#157](https://github.com/PSKeePass/PoShKeePass/issues/157) - Set New-KPConnection function back to internal function and no longer exports.

## v.2.1.2.4

* Added Feature [#29](https://github.com/PSKeePass/PoShKeePass/issues/29) - Can now manage the Expiration Time/Enabled State of groups and entry.

* v.2.1.2.3 - Fix [#64](https://github.com/PSKeePass/PoShKeePass/issues/65) - Review Message for grammar, clarified some messages as well.

* v.2.1.2.2 - Fix [#156](https://github.com/PSKeePass/PoShKeePass/issues/156) - New-KeePassDatabase will now error out if kdbx file already exists, instead of silently overwriting an existing file.

* v.2.1.2.1 - Fix [#149](https://github.com/PSKeePass/PoShKeePass/issues/149) - **Breaking Change** New-KeePassGroup and Update-KeePassGroup now return a KeePass PSObject via the ConvertTo-KPPsObject function.

## v.2.1.2.0

* Fix [#148](https://github.com/PSKeePass/PoShKeePass/issues/148) - Can now update an entry multiple times, while retaining history and not through internal lib exception
* Changes to build script

## v2.1.1.8

### Many fixes, features and improvements, please note the **Breaking Changes** Below

* Fix [#129](https://github.com/PSKeePass/PoShKeePass/issues/129) - Can now pass Credential Object to `-MasterKey` Parameter
* Fix/Implemented [#69](https://github.com/PSKeePass/PoShKeePass/issues/69) - All primary Functions return a Powershell object rather than a KeePass Object **This Includes Breaking changes!**.
  * **Breaking:**
    * Since a powershell object is now returned, in order to access the keepass object a child property has been added to the ps object, `.KPEntry` and `.KPGroup`.
    * Deprecated the `-AsPlainText` parameter on the `Get-KeePassGroup` function, the call will still work but it will present a warning message. This is being removed as it is no longer necessary.
  * **Non-Breaking:**
    * Moved how database profile name was being added to the ps object for better performance on conversion.
* Implemented [#93](https://github.com/PSKeePass/PoShKeePass/issues/93) - `Get-KeePassEntry` Now supports `-Title` and `-UserName` parameters also via pipeline.
* Normalized Error handling to remove repetitive code
* Converted extraneous logic to parameter splatting
* Code formatting and removed explict parameter attributes where not necessary.
* Updated Object creation to use the `hashtable` method for performance over the `New-Object` + `Add-Memeber`.
* Fix [#44](https://github.com/PSKeePass/PoShKeePass/issues/44) - Pipeline now Works for `Remove-KeePassDatabaseConfiguration`.
* Implemented [#141](https://github.com/PSKeePass/PoShKeePass/issues/141) - Much stronger Pipeline support.
  * `-DatabaseProfileName` no longer needs to be specified to a KPPSObject pipeline recieving function.
    * Example: `Get-KeePassEntry -Title 'test' -DatabaseProfileName 'profile' | Remove-KeePassEntry`
  * All parent and object paths now are recieved by the pipeline which of course can be overridden by specifing the parameter.
* Fixed [#140](https://github.com/PSKeePass/PoShKeePass/issues/140) and [#138](https://github.com/PSKeePass/PoShKeePass/issues/138) - by removing the `EncodeKeePassLib.ps1` script file as it is no longer in use.
* Fixed [#144](https://github.com/PSKeePass/PoShKeePass/issues/144) - Removed Faultly logic which allowed for the KeePass Icon to get set to blank while updating an object.
* Implemented [#143](https://github.com/PSKeePass/PoShKeePass/issues/143) There are no more dynamic parameters! So all of the gitches have left with them. They still support tab completion by using `Register-ArgumentCompleter`.
  * **Breaking Change** as this is only supported in powershell v5 and up, auto complete will not work in older versions.
* Implemented [#118](https://github.com/PSKeePass/PoShKeePass/issues/118) - by adding support for keepasslib version `2.39.1`
  * The new file format version between the previous version of `2.34` and the latest apears to be much slower on some operations.
  * Testing the new Lib version against the previously suported version `2.34` all worked and appears to be backwards compatible. Also it does not upgrade the file format version.
  * Version can easily flipped back by modifying the global variable in the `.psm1` file.
  * This fixes [#131](https://github.com/PSKeePass/PoShKeePass/issues/131).
* Fix [#145](https://github.com/PSKeePass/PoShKeePass/issues/145) - Updating a KeePass Entry now updates the modification time in UTC.
  * **Breaking Change** - Renamed the `LastAccessTime` and `LastModificationTime` properties to `LastAccessTimeUtc` and `LastModificationTimeUtc` to reflect that they are in UTC.
* Addressed [#88](https://github.com/PSKeePass/PoShKeePass/issues/88) - `Get-KeePassEntry`
  * Since a Ps object is now always returned, all fields but the password are in plaintext. Now specifying the `-AsPlainText` will decode the password to plaintext.
    * This gives the user better control over when they expose the password as plaintext if need be.
  * Another improvement is there is now a `-WithCredential` parameter which adds a `.Credential` property to the return Entry PS Object.
    * This is not done by default as it has overhead.
    * This gives the user better options and does not require manual creation of the credential.
    * **Breaking Change** Since this has been implemeneted the `-AsPsCredential` parameter has been removed. The new method is better as it allows for multiple entries to be returned with thier cred objects instead of limiting it to 1 entry.
* **Breaking Change** - `ConvertTo-KPPSObject` and all returned objects the `.FullPath` property now returns the true full path of the object. The `ParentGroup` property still exists and can be used as an alteranative data source for any lost functionality.

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
