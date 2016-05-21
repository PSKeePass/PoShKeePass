# PSKeePass
PowerShell module for KeePass
This Module is based on the work of Jason Fossen at Sans.org (https://cyber-defense.sans.org/blog/2015/08/13/powershell-for-keepass-sample-script)

It´s intent is to make the usage of KeePass (www.keepass.info) as a credential database inside PowerShell scripts as easy
as possible. Please be aware that you should use SecureStrngs, PSCredential objects and Event-Log encryption to keep you secrets save.
More info at:
- Protected Eventlog at https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
- https://blogs.msdn.microsoft.com/powershell/2013/12/16/powershell-security-best-practices/

The module contains the following Cmdlets:

1. Set-KeePassConfiguration
2. Get-KeePassConfiguration
3. Get-KeePassEntry
4. Set-KeePassEntry
5. New-KeePassEntry
6. Get-KeePassLibrary
7. Get-KeePassCredential
8. Get-KeePassConnection
9. Remove-KeePassConnection
10. Get-KeePassEntryBase
11. Add-KeePassEntry
12. Get-KeePassGroup
13. Add-KeePassGroup
14. Get-KeePassPassword
15. ConvertFrom-KeePassProtectedString
16. ConvertTo-KeePassPSObject

The module currently has no suffisticated error-handling!

PSKeePass is tested and running with the followig KeePass versions:

KeePass 2.3.1

## Contributing
If you would like to contribute please review the CONTRIBUTE.md file.
