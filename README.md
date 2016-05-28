# PSKeePass
PowerShell module for KeePass
This Module is based on the work of Jason Fossen at Sans.org (https://cyber-defense.sans.org/blog/2015/08/13/powershell-for-keepass-sample-script)

It´s intent is to make the usage of KeePass (www.keepass.info) as a credential database inside PowerShell scripts as easy
as possible. Please be aware that you should use SecureStrngs, PSCredential objects and Event-Log encryption to keep you secrets save.
More info at:
- Protected Eventlog at https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
- https://blogs.msdn.microsoft.com/powershell/2013/12/16/powershell-security-best-practices/

The module contains the following functions:

Set-KeePassConfiguration
Get-KeePassConfiguration
Get-KeePassEntry
Set-KeePassEntry
New-KeePassEntry

The module currently has no suffisticated error-handling!

PSKeePass is tested and running with the followig KeePass versions:

KeePass 2.3.1



##Contributing

If you would like to contribute please review the CONTRIBUTE.md file.



