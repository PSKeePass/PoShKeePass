#Module Path
$ModulePath =  Resolve-Path -Path "$PSScriptRoot\..\PSKeePass-1\PSKeePass-1.psm1"

#Test Keepass database and key file
$DatabaseFile = Resolve-Path -Path "$PSScriptRoot\..\Test\PSKeePassTestDatabase.kdbx"
$KeyFile = Resolve-Path -Path "$PSScriptRoot\..\Test\PSKeePassTestDatabase.key"

Write-Output "Importing Module"
#import PSKeePass Module
Import-Module -Name $ModulePath -Verbose -Force


Write-Output "Getting KeePass Credential"
#Create a Keepass credential object (used to open a connection to the KPDB)
$KeePassCredential = Get-KeePassCredential -DatabaseFile $DatabaseFile -KeyFile $KeyFile

Write-Output "Getting Keepass Connection"
#Open a connection to the KPDB
$KeePassConnection = Get-KeePassConnection -KeePassCredential $KeePassCredential

Write-Output "Getting Keepass Group"
#Get a Keepass Group Object
$KeePassGroup = Get-KeePassGroup -KeePassConnection $KeePassConnection -FullPath 'General'

Write-Output "Adding KeePass Group"
# #Add a KeePass group
Add-KeePassGroup -KeePassConnection $KeePassConnection -GroupName 'TestGroup1' -KeePassParentGroup $KeePassGroup

Write-Output "Getting KeePass Group"
#Get the KeePass Group we just added.
$NewKeePassGroup = Get-KeePassGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestGroup1'

Write-Output "Generating New KeePass Password"
#Generate a New Password
$NewKeePassPassword = Get-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 20

Write-Output "Adding New KeePass Entry"
# #Add a new KeePass Entry
Add-KeePassEntry -KeePassConnection $KeePassConnection -KeePassGroup $NewKeePassGroup -Title 'TestTitle1' -UserName 'TestUserName1' -KeePassPassword $NewKeePassPassword  -Notes 'This is a test entry.' -URL 'http://TestURL.com'

Write-Output "Getting a KeePass Entry"
# #Get the KeePass Entry that was Just added
$KeePassEntry = Get-KeePassEntryBase -KeePassConnection $KeePassConnection -KeePassGroup $NewKeePassGroup -Title 'TestTitle1'

Write-Output "This is a fetched KeePass Entry:"
# #Show that entry
$KeePassEntry

Write-Output "Convert a KeePass Entry to a PSObject"
# #convert that entry a PS Object and convert the secure strings to text
$KeePassPSObject = ConvertTo-KeePassPSObject -KeePassEntry $KeePassEntry 

Write-Output "This is a KeePass Entry as a PSObject:"
# #show that psobject
$KeePassPSObject 

Write-Output "Closing KeePass Connection"
#Close and Remove Connecion to the KPDB
Remove-KeePassConnection -KeePassConnection $KeePassConnection