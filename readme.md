# PowerShell KeePass
[PoShKeePass](https://www.powershellgallery.com/packages/PoShKeePass) is a PowerShell module that combines the ease of the PowerShell cli and the extensibility of the [KeePassLib API](http://keepass.info/help/v2/setup.html) to provide a powerful and easy to use management and automating platform for [KeePass](http://keepass.info/) databases.

## Features
1. **Database Configuration Profiles** - Supports mutliple databases and authentication options.
2. **Getting, Creating, Updating, and Removing KeePass Entries and Groups** - All of these perform as much automatic database authentication as possible using the database configuration profile. For databases that use a masterkey (password) it will prompt for it.
3. **Generating KeePass Passwords** - Supports most character sets and advanced keepass options. Also supports creating password profiles that can be specified to create a new password with the same rule set.

## Getting Started

### Install
```powershell
Install-Module -Name PoShKeePass
```

### Documentation
Please check out our [Getting Started](https://github.com/PSKeePass/PoShKeePass/wiki/Getting-Started) documentation on our [wiki](https://github.com/PSKeePass/PoShKeePass/wiki).

## Important Notes & Reminders
1. Please always keep up to date **backups** of your KeePass database files .kdbx and .key files.
2. The module uses the KeePassLib 2.3.x which is embedded in the module file.
3. This module was built and tested in PowerShell 5 on Windows 10 but should work in PowerShell 4 and Windows 8.1 and Server 2012 R2 and up. It may work in some earlier versions but is currently untested and not supported. If you come across issues create an issue and I will look into fixing it or create a pull request.
4. There is an underlying framework that I wrote into the module to make all of the api calls that I will eventually expose for advanced scripting.

## Changelog
Please review the [changelog document](https://github.com/PSKeePass/PoShKeePass/blob/master/changelog.md) for a full history.

## Changelog PoShKeePass v2.0.4.1
* [#132](https://github.com/PSKeePass/PoShKeePass/issues/132) Fixed - Windows Defender identifies PoshKeepass as trojan. Please see the issue for more details.

### Changelog PoShKeePass v2.0.4.0
* #108 Fixed bug by capturing PSCredential to MasterKey variable.

### Changelog PoShKeePass v2.0.3.9

1. #92 Added PowerShell Format XML File for creating PowerShell Object views.
2. #90 Updated default properties returned for KeePass Entries to Include the Notes Property. Did this via the new format XML file.
3. #67 Consolidated KeePass database connection and authentication functions. Thanks @Ninjigen for your help on this.
4. #67 Now supports authentication using all three methods as a combination: MasterKey, KeyFile, WindowsAccount. 
5. #100 Fixed bug when using the `-MasterKey` options on and of the functions. The proper variable is now removed.
6. #95 Added internal function `Restore-KPConfigurationFile`. This is implemented to restore your configuration file from a previous version of the module, when updating from PSGallery.
7. Moved exported functions to the Module Manifest.

### Changelog PoShKeePass v2.0.3.1

#### Issue #79 - Added support Icon Management
* Updated `New` and `Update` Entry and Group functions to support setting and
updating Icon values.
* Update `ConvertTo-KPPSObject` to output the IconId.
* Added Pester Tests for adding and updating Icons.
* Update `Get-KPDynamicParameters` to support creating the Icon dynamic
param from the `KeePassLib.PwIcon` Enum.

## Known Issues
See the [Known-Issue](https://github.com/PSKeePass/PoShKeePass/issues?q=is%3Aissue+is%3Aopen+label%3AKnown-Issue) tag to get a list of known issues and their status.

## Contributing
* If you are insterested in fixing issues and contributing directly to the code base, please see the documentation on [How to Contribute](https://github.com/PSKeePass/PoShKeePass/blob/master/contribute.md).
* If you come across a bug or have a feature request feel free to create an issue with the appropriate label.

## Shout-Outs
* PSKeePass would like to thank [Jason Fossen](https://github.com/JasonFossen) for his [initial work](https://cyber-defense.sans.org/blog/2015/08/13/powershell-for-keepass-sample-script) with KeePass in PowerShell.
* PSKeePass would like to thank [Andrzej Pilacik](http://www.apdba.com/) (aka @cypisek77) for his review and feedback on documentation and over all rubber ducking.

## License
Copyright (c) [John Klann](https://github.com/jkdba), [Christian Lehrer](https://github.com/chritea). All rights reserved.

Licensed under the [MIT](https://github.com/PSKeePass/PoShKeePass/blob/master/license) License.
