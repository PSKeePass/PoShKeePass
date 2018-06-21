Get-Module PoShKeePass | Remove-Module
Import-Module "$PSScriptRoot\..\PoShKeePass.psm1" -force -ErrorAction Stop

InModuleScope "PoShKeePass" {

    Import-KPLibrary

    $WarningPreference = 'SilentlyContinue'

    Describe "New-KPConnection - UnitTest" -Tag UnitTest {

        Context "Example 1: Open with PSKeePass Credential Object - KeyFile" {

            It "Example 1.1: Get KeePass Database Connection with KeyFile - Valid" {
                $KeePassConnection = New-KPConnection -Database "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key"
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'KeyFile'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        Context "Example 2: Open with PSKeePass Credential Object - MasterKey" {

            It "Example 2.1: Get KeePass Database Connection with MasterKey - Valid" {
                $KeePassConnection = New-KPConnection -Database "$PSScriptRoot\Includes\AuthenticationDatabases\MasterKey.kdbx" -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'MasterKey'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        Context "Example 3: Open with PSKeePass Credential Object - MasterKey and KeyFile" {

            It "Example 3.1: Get KeePass Database Connection with KeyAndMaster - Valid" {
                $KeePassConnection = New-KPConnection -Database "$PSScriptRoot\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyAndMaster.key" -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'KeyAndMaster'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }

            It "Example 3.2: Get KeePass Database Connection with KeyAndMaster - Invalid Key File" {
                { New-KPConnection -Database "$PSScriptRoot\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key" -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force) } | Should Throw
            }
        }

        ## Holding off on Network Account Testing until I can script the creation of a database.
    }

    Describe "Remove-KPConnection - UnitTest" -Tag UnitTest {

        Context "Example 1: Close an Open PSKeePass Database Connection" {

            It "Example 1.1: Closes a KeePass Database Connection" {
                $KeePassConnection = New-KPConnection -Database "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key"
                $KeePassConnection.IsOpen | Should Be $true
                Remove-KPConnection -KeePassConnection $KeePassConnection | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }
    }

    Describe "New-KPConfigurationFile - UnitTest" -Tag UnitTest {

        Context "Example 1: Create a new KeePass Database Configuration XML File" {

            It "Example 1.1: Creates a New Config File - Valid" {
                if((Test-Path -Path "$($PSScriptRoot)\..\KeePassConfiguration.xml"))
                {
                    Remove-Item -Path "$($PSScriptRoot)\..\KeePassConfiguration.xml" -Force
                }
                New-KPConfigurationFile | Should Be $null
                Test-Path -Path "$($PSScriptRoot)\..\KeePassConfiguration.xml"
            }

            It "Example 1.2: Creates a New Config File - Invalid" {
                { New-KPConfigurationFile } | Should Throw "A KeePass Configuration File already exists."
            }

            It "Example 1.3: Creates a New Config File with OverWrite - Valid" {
                New-KPConfigurationFile -Force | Should Be $null
                Test-Path -Path "$($PSScriptRoot)\..\KeePassConfiguration.xml"
            }
        }
    }

    Describe "New-KeePassDatabaseConfiguration - UnitTest" -Tag UnitTest {

        Context "Example 1: Create a new KeePass Database Configuration Profile - KeyFile" {

            New-KPConfigurationFile -Force

            It "Example 1.1: Database Configuration Profile - KeyFile - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key" | Should Be $null
            }

            It "Example 1.2: Database Configuration Profile - KeyFile - Invalid Exists" {
                {New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key" } | Should Throw
            }

            It "Example 1.3: Database Configuration Profile - KeyFile - Valid with PassThru" {
                $DatabaseConfiguration = New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileTestPassThru' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyPath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyFile.key" -PassThru

                $DatabaseConfiguration.Name | Should Be 'KeyFileTestPassThru'
                $DatabaseConfiguration.DatabasePath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyFile.kdbx"
                $DatabaseConfiguration.KeyPath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyFile.key"
                $DatabaseConfiguration.UseNetworkAccount | Should Be $false
                $DatabaseConfiguration.UseMasterKey | Should Be $false
                $DatabaseConfiguration.AuthenticationType | Should Be 'Key'
            }
            break
        }

        Context "Example 2: Create a new KeePass Database Configuration Profile - MasterKey" {

            New-KPConfigurationFile -Force

            It "Example 2.1: Database Configuration Profile - MasterKey - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'MasterKeyTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseMasterKey | Should Be $null
            }

            It "Example 2.2: Database Configuration Profile - MasterKey - Invalid Exists" {
                {New-KeePassDatabaseConfiguration -DatabaseProfileName 'MasterKeyTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseMasterKey } | Should Throw
            }

            It "Example 2.3: Database Configuration Profile - MasterKey - Valid with PassThru" {
                $DatabaseConfiguration = New-KeePassDatabaseConfiguration -DatabaseProfileName 'MasterKeyTestPassThru' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseMasterKey -PassThru

                $DatabaseConfiguration.Name | Should Be 'MasterKeyTestPassThru'
                $DatabaseConfiguration.DatabasePath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx"
                $DatabaseConfiguration.KeyPath | Should Be ''
                $DatabaseConfiguration.UseNetworkAccount | Should Be 'False'
                $DatabaseConfiguration.UseMasterKey | Should Be 'True'
                $DatabaseConfiguration.AuthenticationType | Should Be 'Master'
            }
        }

        Context "Example 3: Create a new KeePass Database Configuration Profile - KeyFile And MasterKey" {

            New-KPConfigurationFile -Force

            It "Example 3.1: Database Configuration Profile - KeyFile And MasterKey - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileAndMasterKeyTest' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.key" -UseMasterKey | Should Be $null
            }

            It "Example 3.2: Database Configuration Profile - KeyFile And MasterKey - Invalid Exists" {
                {New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileAndMasterKeyTest' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.key" -UseMasterKey } | Should Throw
            }

            It "Example 3.3: Database Configuration Profile - KeyFile And MasterKey - Valid with PassThru" {
                $DatabaseConfiguration = New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileAndMasterKeyTestPassThru' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.key" -UseMasterKey -PassThru

                $DatabaseConfiguration.Name | Should Be 'KeyFileAndMasterKeyTestPassThru'
                $DatabaseConfiguration.DatabasePath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.kdbx"
                $DatabaseConfiguration.KeyPath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.key"
                $DatabaseConfiguration.UseNetworkAccount | Should Be 'False'
                $DatabaseConfiguration.UseMasterKey | Should Be 'True'
                $DatabaseConfiguration.AuthenticationType | Should Be 'KeyAndMaster'
            }

            It "Example 3.4: Database Configuration Profile - KeyFile And MasterKey with NetworkAccount - Invalid Authentication Combo" {
                {New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileAndMasterKeyAndNetworkAuthenticationTest' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.key" -UseMasterKey -UserNetworkAccount} | Should Throw
            }
        }

        Context "Example 4: Create a new KeePass Database Configuration Profile - Network" {

            New-KPConfigurationFile -Force

            It "Example 4.1: Database Configuration Profile - Network - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'NetworkTest' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null
            }

            It "Example 4.2: Database Configuration Profile - Network - Invalid Exists" {
                {New-KeePassDatabaseConfiguration -DatabaseProfileName 'NetworkTest' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount } | Should Throw
            }

            It "Example 4.3: Database Configuration Profile - Network - Valid with PassThru" {
                $DatabaseConfiguration = New-KeePassDatabaseConfiguration -DatabaseProfileName 'NetworkTestPassThru' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount -PassThru

                $DatabaseConfiguration.Name | Should Be 'NetworkTestPassThru'
                $DatabaseConfiguration.DatabasePath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx"
                $DatabaseConfiguration.KeyPath | Should Be ''
                $DatabaseConfiguration.UseNetworkAccount | Should Be 'True'
                $DatabaseConfiguration.UseMasterKey | Should Be 'False'
                $DatabaseConfiguration.AuthenticationType | Should Be 'Network'
            }
        }
    }

    Describe "Get-KeePassDatabaseConfiguration - UnitTest" -Tag UnitTest {
        New-KPConfigurationFile -Force

        Context "Example 1: Get a KeePass Database Configuration Profile" {

            It "Example 1.1: Get Database Configuration Profile - Valid - By Name" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                $DatabaseConfiguration = Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile'

                $DatabaseConfiguration.Name | Should Be 'SampleProfile'
                $DatabaseConfiguration.DatabasePath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx"
                $DatabaseConfiguration.KeyPath | Should Be ''
                $DatabaseConfiguration.UseNetworkAccount | Should Be 'True'
                $DatabaseConfiguration.UseMasterKey | Should Be 'False'
                $DatabaseConfiguration.AuthenticationType | Should Be 'Network'
            }

            It "Example 1.2: Get Database Configuration Profile - Valid - All" {
                $DatabaseConfiguration = Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile'

                $DatabaseConfiguration.Name | Should Be 'SampleProfile'
                $DatabaseConfiguration.DatabasePath | Should Be "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx"
                $DatabaseConfiguration.KeyPath | Should Be ''
                $DatabaseConfiguration.UseNetworkAccount | Should Be 'True'
                $DatabaseConfiguration.UseMasterKey | Should Be 'False'
                $DatabaseConfiguration.AuthenticationType | Should Be 'Network'
            }
        }

        New-KPConfigurationFile -Force
    }

    Describe "Remove-KeePassDatabaseConfiguration - UnitTest" -Tag UnitTest {
        New-KPConfigurationFile -Force

        Context "Example 1: Remove a KeePass Database Configuration Profile" {

            It "Example 1.1: Remove Database Configuration Profile - Valid - By Name" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                # Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile'

                Remove-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -confirm:$false | Should Be $null

                Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' | Should Be $null
            }

            It "Example 1.2: Remove Database Configuration Profile - Valid - By Name - Via Pipeline" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' | Remove-KeePassDatabaseConfiguration -confirm:$false | Should Be $null

                Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' | Should Be $null
            }

            It "Example 1.3: Remove Database Configuration Profile - Valid - Multiple - Via Pipeline" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile1' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                Get-KeePassDatabaseConfiguration | Remove-KeePassDatabaseConfiguration -confirm:$false | Should Be $null

                Get-KeePassDatabaseConfiguration | Should Be $null
            }
        }

        New-KPConfigurationFile -Force
    }

    Describe "New-KPConnection - Profile - UnitTest" -Tag UnitTest {

        Context "Example 1: Open with PSKeePass Credential Object - KeyFile - Profile" {
            New-KPConfigurationFile -Force

            It "Example 1.1: Get KeePass Database Connection with KeyFile from a Profile- Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyPath "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key" | Should Be $null
                $KeePassConnection = New-KPConnection -DatabaseProfileName 'KeyFileTest'
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'KeyFile'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        Context "Example 2: Open with PSKeePass Credential Object - MasterKey - Profile" {
            New-KPConfigurationFile -Force

            It "Example 2.1: Get KeePass Database Connection with MasterKey from a Profile - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'MasterKeyTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseMasterKey | Should Be $null
                $KeePassConnection = New-KPConnection -DatabaseProfileName 'MasterKeyTest' -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'MasterKey'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        Context "Example 3: Open with PSKeePass Credential Object - MasterKey and KeyFile - Profile" {
            New-KPConfigurationFile -Force

            It "Example 3.1: Get KeePass Database Connection with KeyAndMaster from a Profile - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'KeyFileAndMasterKeyTest' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyPath "$($PSScriptRoot)\Includes\AuthenticationDatabases\KeyAndMaster.key" -UseMasterKey | Should Be $null
                $KeePassConnection = New-KPConnection -DatabaseProfileName 'KeyFileAndMasterKeyTest' -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'KeyAndMaster'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        ## Holding off on Network Account Testing until I can script the creation of a database.
    }

    Describe "New-KeePassPassword - UnitTest" -Tag UnitTest {

        Context "Example 1: Generate a new KeePass Password - Options" {

            It "Example 1.1: New Password using all basic options - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 | Should BeOfType KeePassLib.Security.ProtectedString
            }

            It "Example 1.2: New Password using all basic options + ExcludeLookALike - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -ExcludeLookALike | Should BeOfType KeePassLib.Security.ProtectedString
            }

            It "Example 1.3: New Password using all basic options + NoRepeatingCharacters - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -NoRepeatingCharacters | Should BeOfType KeePassLib.Security.ProtectedString
            }

            It "Example 1.4: New Password using some basic options + NoRepeatingCharacters - Invalid" {
                { New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 85 -NoRepeatingCharacters } | Should Throw 'Unabled to generate a password with the specified options.'
            }

            It "Example 1.5: New Password using all basic options + ExcludedCharactes - Valid" {
                $SecurePass = New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 70 -ExcludeCharacters '1,],-a'

                $SecurePass |  Should BeOfType KeePassLib.Security.ProtectedString

                $SecurePass.ReadString() | Should Not Match ([regex]::Escape("^.*[1\]-a].*$"))
            }
        }

        Context "Example 2: Generate a new KeePass Password - Options - SaveAs" {

            New-KPConfigurationFile -Force

            It "Example 2.1: New Password using all basic options - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -SaveAs 'Basic20' | Should BeOfType KeePassLib.Security.ProtectedString

                $PassProfile = Get-KPPasswordProfile -PasswordProfileName 'Basic20'
                $PassProfile.Name | Should Be 'Basic20'
                $PassProfile.CharacterSet | Should Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&''*+,./:;=?@\^`|~-_ []{}()<>'
                $PassProfile.ExcludeLookAlike | Should Be 'False'
                $PassProfile.NoRepeatingCharacters | Should Be 'False'
                $PassProfile.ExcludeCharacters | Should Be ''
                $PassProfile.Length | Should Be 20
            }

            It "Example 2.2: New Password using all basic options + ExcludeLookALike - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -ExcludeLookALike -SaveAs 'BasicNoLookAlike20' | Should BeOfType KeePassLib.Security.ProtectedString

                $PassProfile = Get-KPPasswordProfile -PasswordProfileName 'BasicNoLookAlike20'
                $PassProfile.Name | Should Be 'BasicNoLookAlike20'
                $PassProfile.CharacterSet | Should Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&''*+,./:;=?@\^`|~-_ []{}()<>'
                $PassProfile.ExcludeLookAlike | Should Be 'True'
                $PassProfile.NoRepeatingCharacters | Should Be 'False'
                $PassProfile.ExcludeCharacters | Should Be ''
                $PassProfile.Length | Should Be 20
            }

            It "Example 2.3: New Password using all basic options + NoRepeatingCharacters - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -NoRepeatingCharacters -SaveAs 'BasicNoRepeat20' | Should BeOfType KeePassLib.Security.ProtectedString

                $PassProfile = Get-KPPasswordProfile -PasswordProfileName 'BasicNoRepeat20'
                $PassProfile.Name | Should Be 'BasicNoRepeat20'
                $PassProfile.CharacterSet | Should Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&''*+,./:;=?@\^`|~-_ []{}()<>'
                $PassProfile.ExcludeLookAlike | Should Be 'False'
                $PassProfile.NoRepeatingCharacters | Should Be 'True'
                $PassProfile.ExcludeCharacters | Should Be ''
                $PassProfile.Length | Should Be 20
            }

            It "Example 2.4: New Password using some basic options + NoRepeatingCharacters - Invalid" {
                { New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 85 -NoRepeatingCharacters -SaveAs 'BasicNoRepeatInvalid' } | Should Throw 'Unabled to generate a password with the specified options.'

                Get-KPPasswordProfile -PasswordProfileName 'BasicNoRepeatInvalid' | Should Be $null
            }

            It "Example 2.5: New Password using all basic options + ExcludedCharactes - Valid" {
                $SecurePass = New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 70 -ExcludeCharacters '1,],-a' -SaveAs 'BasicExcudle1]-a'

                $SecurePass | Should BeOfType KeePassLib.Security.ProtectedString
                $SecurePass.ReadString() | Should Not Match ([regex]::Escape("^.*[1\]-a].*$"))

                $PassProfile = Get-KPPasswordProfile -PasswordProfileName 'BasicExcudle1]-a'
                $PassProfile.Name | Should Be 'BasicExcudle1]-a'
                $PassProfile.CharacterSet | Should Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&''*+,./:;=?@\^`|~-_ []{}()<>'
                $PassProfile.ExcludeLookAlike | Should Be 'False'
                $PassProfile.NoRepeatingCharacters | Should Be 'False'
                $PassProfile.ExcludeCharacters | Should Be '1,],-a'
                $PassProfile.Length | Should Be 70
            }
        }

        Context "Example 3: Generate a new KeePass Password - Profile" {

            It "Example 3.1: New Password using Profile Basic20 - Valid" {
                New-KeePassPassword -PasswordProfileName 'Basic20' | Should BeOfType KeePassLib.Security.ProtectedString
            }

            It "Example 3.2: New Password using Profile BasicNoLookAlike20 - Valid" {
                New-KeePassPassword -PasswordProfileName 'BasicNoLookAlike20' | Should BeOfType KeePassLib.Security.ProtectedString
            }

            It "Example 3.3: New Password using Profile BasicNoRepeat20 - Valid" {
                New-KeePassPassword -PasswordProfileName 'BasicNoRepeat20' | Should BeOfType KeePassLib.Security.ProtectedString
            }

            It "Example 3.4: New Password using Profile BasicNoRepeatInvalid - Invalid - Does Not Exist" {
                { New-KeePassPassword -PasswordProfileName 'BasicNoRepeatInvalid' } | Should Throw
            }

            It "Example 3.5: New Password using Profile BasicExcudle1]-a - Valid" {
                $SecurePass = New-KeePassPassword -PasswordProfileName 'BasicExcudle1]-a'

                $SecurePass | Should BeOfType KeePassLib.Security.ProtectedString
                $SecurePass.ReadString() | Should Not Match ([regex]::Escape("^.*[1\]-a].*$"))
            }
        }
    }

    Describe "New-KeePassEntry - UnitTest" -Tag UnitTest {

        Context "Example 1: Creates a New KeePass Entry." {

            New-KPConfigurationFile -Force

            # It "Example 1.1: Creates a New KeePass Entry - Invalid - No Profile" {
            #     # New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null
            #     { New-KeePassEntry -KeePassEntryGroupPath 'database' -Title 'test' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' } | Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2: Creates a New KeePass Entry - Valid" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
            }

            It "Example 1.3: Creates a New KeePass Entry - Valid - PassThru" {

                $PassThruResult = New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'testPassThru' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' -PassThru

                $PassThruResult.KPEntry | Should BeOfType KeePassLib.PwEntry
                $PassThruResult.KPEntry.ParentGroup.Name | Should BeLike 'PSKeePassTestDatabase'
                $PassThruResult.KPEntry.Strings.ReadSafe('Title') | Should Be 'testPassThru'
                $PassThruResult.KPEntry.Strings.ReadSafe('UserName') | Should Be 'testuser'
                $PassThruResult.KPEntry.Strings.ReadSafe('Notes') | Should Be 'testnotes'
                $PassThruResult.KPEntry.Strings.ReadSafe('URL') | Should be 'http://url.test.com'
            }

            It "Example 1.4: Creates a New KeePass Entry - Invalid - Group Path does not Exist" {
                { New-KeePassEntry -KeePassEntryGroupPath 'BadPath' -Title 'test' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' } | Should Throw
            }

            It "Example 1.5: Creates a New KeePass Entry with manaully specified Password - Valid" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'testPass' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -KeePassPassword $(ConvertTo-SecureString -String 'teststring' -AsPlainText -Force) -DatabaseProfileName 'SampleProfile' | Should Be $null
            }

            It "Example 1.6: Creates a New KeePass Entry with a generated Password - Valid" {
                $GeneratedPassword = New-KeePassPassword -Upper -Lower -Digits -Length 50

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'testPass' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -KeePassPassword $GeneratedPassword -DatabaseProfileName 'SampleProfile' | Should Be $null
            }

            It "Example 1.7: Creates a New KeePass Entry - Valid - PassThru - Icon" {

                $PassThruResult = New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'testPassThruIcon' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' -IconName Apple -PassThru

                $PassThruResult.KPEntry | Should BeOfType KeePassLib.PwEntry
                $PassThruResult.KPEntry.ParentGroup.Name | Should BeLike 'PSKeePassTestDatabase'
                $PassThruResult.KPEntry.Strings.ReadSafe('Title') | Should Be 'testPassThruIcon'
                $PassThruResult.KPEntry.Strings.ReadSafe('UserName') | Should Be 'testuser'
                $PassThruResult.KPEntry.Strings.ReadSafe('Notes') | Should Be 'testnotes'
                $PassThruResult.KPEntry.Strings.ReadSafe('URL') | Should Be 'http://url.test.com'
                $PassThruResult.KPEntry.IconId | Should Be 'Apple'
            }
        }

        New-KPConfigurationFile -Force
    }

    Describe "Get-KeePassEntry - UnitTest" -Tag UnitTest {

        Context "Example 1: Gets KeePass Entries." {

            New-KPConfigurationFile -Force

            # It "Example 1.1: Gets All KeePass Entries - Invalid - No Database Configuration Profiles." {

            #     { Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' } | Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2 Gets All KeePass Entries - Valid" {
                $ResultEntries = Get-KeePassEntry -DatabaseProfileName SampleProfile
                $ResultEntries.Count | Should Be 2
            }

            It "Example 1.2 Gets All KeePass Entries - MasterKey Profile - Valid" {
                New-KeePassDatabaseConfiguration -DatabaseProfileName 'MasterKeyTest' -DatabasePath "$PSScriptRoot\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseMasterKey | Should Be $null
                $ResultEntries = Get-KeePassEntry -DatabaseProfileName 'MasterKeyTest' -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $ResultEntries.Count | Should Be 2
            }

            It "Example 1.3 Gets All KeePass Entries - Valid As Plain Text" {
                $ResultEntries = Get-KeePassEntry -DatabaseProfileName SampleProfile
                $ResultEntries.Count | Should Be 2
                $ResultEntries[0].Title | Should Be 'Sample Entry'
                $ResultEntries[1].Title | Should Be 'Sample Entry #2'
            }

            It "Example 1.4: Gets All KeePass Entries Of Specific Group - Valid" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase/General' -Title 'SubGroupTest' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null

                $ResultEntries = Get-KeePassEntry -DatabaseProfileName SampleProfile -KeePassEntryGroupPath 'PSKeePassTestDatabase/General'
                $ResultEntries.Title | Should Be 'SubGroupTest'
            }

            It "Example 1.5: Gets All KeePass Entries Of Specific Group - Invalid - Bad Path" {

                { Get-KeePassEntry -DatabaseProfileName SampleProfile -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' } | Should Throw
            }

        }

        New-KPConfigurationFile -Force
    }

    Describe "Update-KeePassEntry - UnitTest" -Tag UnitTest {

        Context "Example 1: Updates a KeePass Entry." {

            New-KPConfigurationFile -Force

            # It "Example 1.1: Creates a New KeePass Entry - Invalid - No Profile" {
            #     { Update-KeePassEntry -KeePassEntry $( New-Object KeePassLib.PwEntry($true, $true)) -KeePassEntryGroupPath 'database' -Title 'test' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' }| Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2: Updates a KeePass Entry - Valid - Properties" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test1' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test1' }
                Update-KeePassEntry -KeePassEntry $KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -title 'UpdateTest1' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -DatabaseProfileName 'SampleProfile' -Force | Should Be $null
            }

            It "Example 1.3: Updates a KeePass Entry - Valid - Properties - Via Pipeline" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test2' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test2' } |
                    Update-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -title 'UpdateTest2' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -Force | Should Be $null
            }

            It "Example 1.4: Update a KeePass Entry - Valid - Properties - PassThru" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test3' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test3' }
                $UpdatePassThruResult = Update-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -KeePassEntry $KeePassEntry -title 'UpdateTest3' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -DatabaseProfileName 'SampleProfile' -PassThru -Force

                $UpdatePassThruResult.KPEntry | Should BeOfType KeePassLib.PwEntry
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('Title') | Should Be 'UpdateTest3'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('UserName') | Should Be 'UpdateTestUser'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('Notes') | Should Be 'UpdateTestNotes'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('URL') | Should Be 'http://UpdateURL.Test.com'
            }

            It "Example 1.5: Update a KeePass Entry - Valid - Group & Properties - PassThru" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test4' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test4' }
                $UpdatePassThruResult = Update-KeePassEntry -KeePassEntry $KeePassEntry -title 'UpdateTest4' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -KeePassEntryGroupPath 'PSKeePassTestDatabase/General' -DatabaseProfileName 'SampleProfile' -PassThru -Force

                $UpdatePassThruResult.KPEntry | Should BeOfType KeePassLib.PwEntry
                $UpdatePassThruResult.KPEntry.ParentGroup.Name | Should Be 'General'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('Title') | Should Be 'UpdateTest4'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('UserName') | Should Be 'UpdateTestUser'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('Notes') | Should Be 'UpdateTestNotes'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('URL') | Should Be 'http://UpdateURL.Test.com'
            }

            It "Example 1.6: Update a KeePass Entry - Invalid - Group & Properties - PassThru - BadPath" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test5' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test5' }
                { Update-KeePassEntry -KeePassEntry $KeePassEntry -title 'UpdateTest5' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' -DatabaseProfileName 'SampleProfile' -PassThru -Force } | Should Throw
            }

            It "Example 1.7: Update a KeePass Entry - Valid - Properties - PassThru - Icon" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test6' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test6' }
                $UpdatePassThruResult = Update-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -KeePassEntry $KeePassEntry -title 'UpdateTest6' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -DatabaseProfileName 'SampleProfile' -IconName Apple -PassThru -Force

                $UpdatePassThruResult.KPEntry | Should BeOfType KeePassLib.PwEntry
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('Title') | Should Be 'UpdateTest6'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('UserName') | Should Be 'UpdateTestUser'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('Notes') | Should Be 'UpdateTestNotes'
                $UpdatePassThruResult.KPEntry.Strings.ReadSafe('URL') | Should Be 'http://UpdateURL.Test.com'
                $UpdatePassThruResult.IconId | Should Be 'Apple'
            }
        }
        New-KPConfigurationFile -Force
    }

    Describe "Remove-KeePassEntry - UnitTest" -Tag UnitTest {
        New-KPConfigurationFile -Force

        Context "Example 1: Remove a KeePass Entry" {

            # It "Example 1.1: Removes a KeePass Entry - Invalid - No Profile" {
            #     { Remove-KeePassEntry -KeePassEntry $( New-Object KeePassLib.PwEntry($true, $true)) }| Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"


            It "Example 1.2: Removes a KeePass Entry - Valid " {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test1' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test1' }
                Remove-KeePassEntry -KeePassEntry $KeePassEntry -DatabaseProfileName 'SampleProfile' -Force | Should Be $null
            }

            It "Example 1.3: Removes a KeePass Entry - Valid - NoRecycle " {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test2' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test2' }
                Remove-KeePassEntry -KeePassEntry $KeePassEntry -DatabaseProfileName 'SampleProfile' -NoRecycle -Force | Should Be $null
            }

            It "Example 1.4: Removes a KeePass Entry - Valid - Pipeline " {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test3' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test3' }
                $KeePassEntry | Remove-KeePassEntry -Force | Should Be $null
            }

            It "Example 1.5: Removes a KeePass Entry - Valid - Pipeline - PWEntry" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test4' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -DatabaseProfileName 'SampleProfile' | Where-Object { $_.KPEntry.Strings.ReadSafe('Title') -eq 'test4' }
                $KeePassEntry | Remove-KeePassEntry -Force | Should Be $null
            }
        }

        New-KPConfigurationFile -Force
    }

    Describe "New-KeePassGroup - UnitTest" -Tag UnitTest {

        Context "Example 1: Creates a New KeePass Group." {

            New-KPConfigurationFile -Force

            # It "Example 1.1: Creates a New KeePass Group - Invalid - No Profile" {
            #     { New-KeePassGroup -KeePassGroupParentPath 'database' -KeePassGroupName 'test' } | Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2: Creates a New KeePass Group - Valid" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test1' -DatabaseProfileName 'SampleProfile' | Should Be $null
            }

            It "Example 1.3: Creates a New KeePass Group - Valid - PassThru" {

                $PassThruResult = New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test2PassThru' -DatabaseProfileName 'SampleProfile' -PassThru

                $PassThruResult | Should BeOfType KeePassLib.PwGroup
                $PassThruResult.ParentGroup.Name | Should Be 'PSKeePassTestDatabase'
                $PassThruResult.Name | Should Be 'test2PassThru'
            }

            It "Example 1.4: Creates a New KeePass Entry - Invalid - Group Path does not Exist" {
                { New-KeePassGroup -KeePassGroupParentPath 'BadPath' -KeePassGroupName 'test3' -DatabaseProfileName 'SampleProfile' } | Should Throw
            }

            It "Example 1.5: Creates a New KeePass Group - Valid - PassThru - Icon" {

                $PassThruResult = New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test4PassThru' -DatabaseProfileName 'SampleProfile' -IconName 'Clock' -PassThru

                $PassThruResult | Should BeOfType KeePassLib.PwGroup
                $PassThruResult.ParentGroup.Name | Should Be 'PSKeePassTestDatabase'
                $PassThruResult.Name | Should Be 'test4PassThru'
                $PassThruResult.IconId | Should Be 'Clock'
            }
        }
        New-KPConfigurationFile -Force
    }

    Describe "Get-KeePassGroup - UnitTest" -Tag UnitTest {

        Context "Example 1: Gets KeePass Groups." {

            New-KPConfigurationFile -Force

            # It "Example 1.1: Gets All KeePass Groups - Invalid - No Database Configuration Profiles." {

            #     { Get-KeePassGroup -KeePassGroupPath 'PSKeePassTestDatabase/BadPath' } | Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2 Gets All KeePass Groups - Valid" {
                $ResultGroups = Get-KeePassGroup -DatabaseProfileName SampleProfile
                $ResultGroups.Count | Should Be 7
            }

            It "Example 1.3 Gets All KeePass Groups - Valid As Plain Text" {
                $ResultGroups = Get-KeePassGroup -DatabaseProfileName SampleProfile
                $ResultGroups.Count | Should Be 7
            }

            It "Example 1.4: Gets a KeePass Group - Valid" {

                $ResultGroups = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/General'
                $ResultGroups.Name | Should Be 'General'
                $ResultGroups.ParentGroup | Should Be 'PSKeePassTestDatabase'
            }

            It "Example 1.5: Gets a KeePass Group - Invalid - Bad Path" {

                { Get-KeePassEntry -DatabaseProfileName SampleProfile -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' } | Should Throw
            }

        }

        New-KPConfigurationFile -Force
    }

    Describe "Update-KeePassGroup - UnitTest" -Tag UnitTest {

        Context "Example 1: Updates a KeePass Group." {

            New-KPConfigurationFile -Force

            # It "Example 1.1: Updates a KeePass Group - Invalid - No Profile" {
            #     { Update-KeePassGroup -KeePassGroup $( New-Object KeePassLib.PwGroup($true, $true)) -Force } | Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2: Updates a KeePass Group - Valid - Name" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test1' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test1'
                $KeePassGroup.Name | Should Be 'test1'
                Update-KeePassGroup -KeePassGroup $KeePassGroup -GroupName 'Test1Update' -DatabaseProfileName 'SampleProfile' -Force | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/Test1Update'
                $KeePassGroup.Name | Should Be 'Test1Update'
            }

            It "Example 1.3: Updates a KeePass Group - Valid - Name" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test2' -DatabaseProfileName 'SampleProfile' | Should Be $null
                Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test2' |
                    Update-KeePassGroup -GroupName 'Test2Update' -Force | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/Test2Update'
                $KeePassGroup.Name | Should Be 'Test2Update'
            }

            It "Example 1.4: Updates a KeePass Group - Valid - Name" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test3' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test3'
                $KeePassGroup.Name | Should Be 'test3'
                $KeePassGroup = Update-KeePassGroup -KeePassGroup $KeePassGroup -GroupName 'Test3Update' -DatabaseProfileName 'SampleProfile' -Force -PassThru
                $KeePassGroup.Name | Should Be 'Test3Update'
                $KeePassGroup.ParentGroup.Name | Should be 'PSKeePassTestDatabase'
            }

            It "Example 1.5: Updates a KeePass Group - Valid - ParentGroup - Pipeline" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test4' -DatabaseProfileName 'SampleProfile' | Should Be $null
                Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test4' |
                    Update-KeePassGroup -KeePassParentGroupPath 'PSKeePassTestDatabase/General' -Force | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/General/test4'
                $KeePassGroup.Name | Should Be 'test4'
                $KeePassGroup.ParentGroup | Should be 'General'
            }

            It "Example 1.6: Updates a KeePass Group - Invalid - ParentGroup - BadPath" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test5' -DatabaseProfileName 'SampleProfile' | Should Be $null
                { Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test5' |
                        Update-KeePassGroup -KeePassParentGroupPath 'PSKeePassTestDatabase/BadPath' -Force } | Should Throw
            }

            It "Example 1.7: Updates a KeePass Group - Valid - Name - PassThru - Icon" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test6' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test6'
                $KeePassGroup.Name | Should Be 'test6'
                $KeePassGroup.IconId | Should Be 'Folder'
                $KeePassGroup = Update-KeePassGroup -KeePassGroup $KeePassGroup -GroupName 'Test6Update' -DatabaseProfileName 'SampleProfile' -IconName 'Clock' -Force -PassThru
                $KeePassGroup.Name | Should Be 'Test6Update'
                $KeePassGroup.IconId | Should Be 'Clock'
                $KeePassGroup.ParentGroup.Name | Should be 'PSKeePassTestDatabase'
            }
        }

        New-KPConfigurationFile -Force
    }

    Describe "Remove-KeePassGroup - UnitTest" -Tag UnitTest {
        New-KPConfigurationFile -Force

        Context "Example 1: Remove a KeePass Group" {

            # It "Example 1.1: Removes a KeePass Group - Invalid - No Profile" {
            #     { Remove-KeePassGroup -KeePassGroup $( New-Object KeePassLib.PwGroup($true, $true)) }| Should Throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            # }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"


            It "Example 1.2: Removes a KeePass Group - Valid " {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test1' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test1'
                $KeePassGroup.Name | Should Be 'test1'
                Remove-KeePassGroup -KeePassGroup $KeePassGroup -DatabaseProfileName 'SampleProfile' -Force | Should Be $null
                $Check = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/RecycleBin/test1'
                $Check.Name | Should Be 'test1'
            }

            It "Example 1.3: Removes a KeePass Group - Valid - NoRecycle " {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test2' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test2'
                $KeePassGroup.Name | Should Be 'test2'
                Remove-KeePassGroup -KeePassGroup $KeePassGroup -DatabaseProfileName 'SampleProfile' -NoRecycle -Force | Should Be $null
                Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test2' | Should Be $null
                Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/RecycleBin/test2' | Should Be $null
            }

            It "Example 1.4: Removes a KeePass Group - Valid - Pipeline - AsPlainText" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test3' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test3'
                $KeePassGroup.Name | Should Be 'test3'
                $KeePassGroup | Remove-KeePassGroup -Force | Should Be $null
                Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/RecycleBin/test3' | Should Not Be $null
            }

            It "Example 1.4: Removes a KeePass Group - Valid - Pipeline - PwGroup" {
                New-KeePassGroup -KeePassGroupParentPath 'PSKeePassTestDatabase' -KeePassGroupName 'test4' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassGroup = Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/test4'
                $KeePassGroup.Name | Should Be 'test4'
                $KeePassGroup | Remove-KeePassGroup -Force | Should Be $null
                Get-KeePassGroup -DatabaseProfileName SampleProfile -KeePassGroupPath 'PSKeePassTestDatabase/RecycleBin/test4' | Should Not Be $null
            }
        }

        New-KPConfigurationFile -Force
    }

    ## Reset Test DB
    Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
    Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"
}

$UpdateVersion = Read-Host -Prompt 'Update Version [Y\n]'

if($UpdateVersion -ine 'N')
{
    Invoke-Expression -Command "$($PSScriptRoot)\..\bin\AutoVersion.ps1"
}