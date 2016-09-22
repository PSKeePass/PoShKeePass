Get-Module PSKeePass | Remove-Module
Import-Module "$PSScriptRoot\..\PSKeePass.psm1" -ErrorAction Stop

InModuleScope "PSKeePass" {

    Import-KPLibrary

    $WarningPreference = 'SilentlyContinue'

    Describe "Get-KPCredential - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Mock with Key File and Master Key" {
                    
            It "Example 1.1: Get-KPCredential - Valid Authentication Type: KeyAndMaster" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key" -MasterKey $(ConvertTo-SecureString "AtestPassWord" -AsPlainText -Force)
                $KeePassCredential.DatabaseFile | Should BeLike "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.Key"    
                $KeePassCredential.UseNetworkAccount | Should Be $false
                $KeePassCredential.AuthenticationType | Should Be "KeyAndMaster"
            }

            It "Example 1.2: Get-KPCredential - Valid Authentication Type: KeyAndMaster with Network Account" {
                {Get-KPCredential -DatabaseFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key" -MasterKey $(ConvertTo-SecureString "AtestPassWord" -AsPlainText -Force) -UseNetworkAccount } | Should Throw 
            }
        }
        
        Context "Example 2: Mock with KeyFile" {
            
            It "Example 2.1: Get-KPCredential - Valid Authentication Type: Key" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"
                $KeePassCredential.DatabaseFile | Should BeLike "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.Key"
                $KeePassCredential.UseNetworkAccount | Should Be $false
                $KeePassCredential.AuthenticationType | Should Be "Key"
            }

            It "Example 2.2: Get-KPCredential - Valid Authentication Type: Key with Network Account" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key" -UseNetworkAccount
                $KeePassCredential.DatabaseFile | Should BeLike "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.Key"
                $KeePassCredential.UseNetworkAccount | Should Be $true
                $KeePassCredential.AuthenticationType | Should Be "Key"
            }
        }
        
        Context "Example 3: Mock with MasterKey" {
            
            It "Example 3.1: Get-KPCredential - Valid Authentication Type: MasterKey" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -MasterKey $(ConvertTo-SecureString "AtestPassWord" -AsPlainText -Force)
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should Be ""         
                $KeePassCredential.UseNetworkAccount | Should Be $false
                $KeePassCredential.AuthenticationType | Should Be "Master"
            }

            It "Example 3.2: Get-KPCredential - Valid Authentication Type: MasterKey with Network Account" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -MasterKey $(ConvertTo-SecureString "AtestPassWord" -AsPlainText -Force) -UseNetworkAccount
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should Be ""
                $KeePassCredential.UseNetworkAccount | Should Be $true
                $KeePassCredential.AuthenticationType | Should Be "Master"
            }
        }

        Context "Example 4: Mock with Network Account" {
            
            It "Example 4.1: Get-KPCredential - Valid Authentication Type: NetworkAccount" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -UseNetworkAccount
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should Be ""
                $KeePassCredential.MasterKey | Should Be $null
                $KeePassCredential.UseNetworkAccount | Should Be $true
                $KeePassCredential.AuthenticationType | Should Be "Network"
            }
        }

        Context "Example 5: Mock Invalid Parameter Combination" {
            
            It "Example 5.1: Get-KPCredential - Invalid Authentication: Database Only " {
                { Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" } | Should Throw "Please Specify a valid Credential Combination."
            }
        }
    }

    Describe "Get-KPConnection - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Open with PSKeePass Credential Object - KeyFile" {
            
            It "Example 1.1: Get KeePass Database Connection with KeyFile - Valid" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key"
                $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'KeyFile'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        Context "Example 2: Open with PSKeePass Credential Object - MasterKey" {
            
            It "Example 2.1: Get KeePass Database Connection with MasterKey - Valid" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\AuthenticationDatabases\MasterKey.kdbx" -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'MasterKey'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }

        Context "Example 3: Open with PSKeePass Credential Object - MasterKey and KeyFile" {
            
            It "Example 3.1: Get KeePass Database Connection with KeyAndMaster - Valid" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyAndMaster.key" -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.RootGroup.Name | Should Be 'KeyAndMaster'
                $KeePassConnection.Close() | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }

            It "Example 3.2: Get KeePass Database Connection with KeyAndMaster - Invalid Key File" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyAndMaster.kdbx" -KeyFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key" -MasterKey $(ConvertTo-SecureString -String "ATestPassWord" -AsPlainText -Force)
                { Get-KPConnection -KeePassCredential $KeePassCredential } | Should Throw
            }
        }

        ## Holding off on Network Account Testing until I can script the creation of a database.
    }

    Describe "Remove-KPConnection - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Close an Open PSKeePass Database Connection" {
            
            It "Example 1.1: Closes a KeePass Database Connection" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.kdbx" -KeyFile "$PSScriptRoot\Includes\AuthenticationDatabases\KeyFile.key"
                $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
                $KeePassConnection.IsOpen | Should Be $true
                Remove-KPConnection -KeePassConnection $KeePassConnection | Should Be $null
                $KeePassConnection.IsOpen | Should Be $false
            }
        }
    }

    Describe "New-KPConfigurationFile - UnitTest" -Tag UnitTest {

        Context "Example 1: Create a new KeePass Database Configuration XML File" {

            It "Example 1.1: Creates a New Config File - Valid" {
                if((Test-Path -Path "$($PSScriptRoot)\..\KeePassConfiguration.xml")){
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
                $DatabaseConfiguration.UseNetworkAccount | Should Be 'False'
                $DatabaseConfiguration.UseMasterKey | Should Be 'False'
                $DatabaseConfiguration.AuthenticationType | Should Be 'Key'
            }
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

            <#
                ## On Hold until can figure out pipe line for this
                # It "Example 1.2: Remove Database Configuration Profile - Valid - By Name - Via Pipeline" {
                #     New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                #     Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' | Remove-KeePassDatabaseConfiguration -confirm:$false | Should Be $null 

                #     Get-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' | Should Be $null
                # }
                
                ## On Hold until can figure out pipe line for this
                # It "Example 1.3: Remove Database Configuration Profile - Valid - Multiple - Via Pipeline" {
                #     New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                #     New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile1' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null

                #     Get-KeePassDatabaseConfiguration | Remove-KeePassDatabaseConfiguration -confirm:$false | Should Be $null 

                #     Get-KeePassDatabaseConfiguration | Should Be $null
                # }
            #>
            It "Example 1.2: Remove Database Configuration Profile - Invalid - No Profiles Exist." {

                {Remove-KeePassDatabaseConfiguration -confirm:$false } | Should Throw "There are Currently No Database Configuration Profiles."

                Get-KeePassDatabaseConfiguration | Should Be $null
            }
        }

        New-KPConfigurationFile -Force
    }
    
    Describe "New-KeePassPassword - UnitTest" -Tag UnitTest {

        Context "Example 1: Generate a new KeePass Password - Options" {

            It "Example 1.1: New Password using all basic options - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 | Should BeOfType System.Security.SecureString 
            }

            It "Example 1.2: New Password using all basic options + ExcludeLookALike - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -ExcludeLookALike | Should BeOfType System.Security.SecureString 
            }

            It "Example 1.3: New Password using all basic options + NoRepeatingCharacters - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -NoRepeatingCharacters | Should BeOfType System.Security.SecureString 
            }

            It "Example 1.4: New Password using some basic options + NoRepeatingCharacters - Invalid" {
                { New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 85 -NoRepeatingCharacters } | Should Throw 'Unabled to generate a password with the specified options.'
            }

            It "Example 1.5: New Password using all basic options + ExcludedCharactes - Valid" {
                $SecurePass = New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 70 -ExcludeCharacters '1,],-a'

                $SecurePass |  Should BeOfType System.Security.SecureString
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)) | Should Not Match ([regex]::Escape("^.*[1\]-a].*$")) 
            }
        }

        Context "Example 2: Generate a new KeePass Password - Options - SaveAs" {

            New-KPConfigurationFile -Force

            It "Example 2.1: New Password using all basic options - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -SaveAs 'Basic20' | Should BeOfType System.Security.SecureString

                $PassProfile = Get-KPPasswordProfile -PasswordProfileName 'Basic20'
                $PassProfile.Name | Should Be 'Basic20'
                $PassProfile.CharacterSet | Should Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&''*+,./:;=?@\^`|~-_ []{}()<>'
                $PassProfile.ExcludeLookAlike | Should Be 'False'
                $PassProfile.NoRepeatingCharacters | Should Be 'False'
                $PassProfile.ExcludeCharacters | Should Be ''
                $PassProfile.Length | Should Be 20
            }

            It "Example 2.2: New Password using all basic options + ExcludeLookALike - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -ExcludeLookALike -SaveAs 'BasicNoLookAlike20' | Should BeOfType System.Security.SecureString

                $PassProfile = Get-KPPasswordProfile -PasswordProfileName 'BasicNoLookAlike20'
                $PassProfile.Name | Should Be 'BasicNoLookAlike20'
                $PassProfile.CharacterSet | Should Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&''*+,./:;=?@\^`|~-_ []{}()<>'
                $PassProfile.ExcludeLookAlike | Should Be 'True'
                $PassProfile.NoRepeatingCharacters | Should Be 'False'
                $PassProfile.ExcludeCharacters | Should Be ''
                $PassProfile.Length | Should Be 20 
            }

            It "Example 2.3: New Password using all basic options + NoRepeatingCharacters - Valid" {
                New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Minus -UnderScore -Space -Brackets -Length 20 -NoRepeatingCharacters -SaveAs 'BasicNoRepeat20' | Should BeOfType System.Security.SecureString
                
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

                $SecurePass |  Should BeOfType System.Security.SecureString
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)) | Should Not Match ([regex]::Escape("^.*[1\]-a].*$"))

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
                New-KeePassPassword  -PasswordProfileName 'Basic20' | Should BeOfType System.Security.SecureString
            }

            It "Example 3.2: New Password using Profile BasicNoLookAlike20 - Valid" {
                New-KeePassPassword -PasswordProfileName 'BasicNoLookAlike20' | Should BeOfType System.Security.SecureString
            }

            It "Example 3.3: New Password using Profile BasicNoRepeat20 - Valid" {
                New-KeePassPassword -PasswordProfileName 'BasicNoRepeat20' | Should BeOfType System.Security.SecureString
            }

            It "Example 3.4: New Password using Profile BasicNoRepeatInvalid - Invalid - Does Not Exist" {
                { New-KeePassPassword -PasswordProfileName 'BasicNoRepeatInvalid' } | Should Throw
            }

            It "Example 3.5: New Password using Profile BasicExcudle1]-a - Valid" {
                $SecurePass = New-KeePassPassword -PasswordProfileName 'BasicExcudle1]-a'

                $SecurePass |  Should BeOfType System.Security.SecureString
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)) | Should Not Match ([regex]::Escape("^.*[1\]-a].*$"))
            }
        }
    }

    Describe "New-KeePassEntry - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Creates a New KeePass Entry." {

            New-KPConfigurationFile -Force

            It "Example 1.1: Creates a New KeePass Entry - Invalid - No Profile" {
                # New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\AuthenticationDatabases\MasterKey.kdbx" -UseNetworkAccount | Should Be $null
                { New-KeePassEntry -KeePassEntryGroupPath 'database' -Title 'test' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' }| Should Throw 'There are Currently No Database Configuration Profiles.'
            }

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

                $PassThruResult | Should BeOfType KeePassLib.PwEntry
                $PassThruResult.ParentGroup.Name | Should BeLike 'PSKeePassTestDatabase'
                $PassThruResult.Strings.ReadSafe('Title') | Should Be 'testPassThru'
                $PassThruResult.Strings.ReadSafe('UserName') | Should Be 'testuser'
                $PassThruResult.Strings.ReadSafe('Notes') | Should Be 'testnotes' 
                $PassThruResult.Strings.ReadSafe('URL') | Should be 'http://url.test.com'
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
        }

        New-KPConfigurationFile -Force
    }

    Describe "Get-KeePassEntry - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Gets KeePass Entries." {

            New-KPConfigurationFile -Force

            It "Example 1.1: Gets All KeePass Entries - Invalid - No Database Configuration Profiles." {

                { Get-KeePassEntry -AsPlainText -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' } | Should Throw 'There are Currently No Database Configuration Profiles.'
            }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2 Gets All KeePass Entries - Valid" {
                $ResultEntries = Get-KeePassEntry -DatabaseProfileName SampleProfile
                $ResultEntries.Count | Should Be 2
            }

            It "Example 1.3 Gets All KeePass Entries - Valid As Plain Text" {
                $ResultEntries = Get-KeePassEntry -DatabaseProfileName SampleProfile -AsPlainText
                $ResultEntries.Count | Should Be 2
                $ResultEntries[0].Title | Should Be 'Sample Entry'
                $ResultEntries[1].Title | Should Be 'Sample Entry #2'
            }

            It "Example 1.4: Gets All KeePass Entries Of Specific Group - Valid" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase/General' -Title 'SubGroupTest' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null

                $ResultEntries = Get-KeePassEntry -DatabaseProfileName SampleProfile -AsPlainText -KeePassEntryGroupPath 'PSKeePassTestDatabase/General'
                $ResultEntries.Title | Should Be 'SubGroupTest'
            }

            It "Example 1.5: Gets All KeePass Entries Of Specific Group - Invalid - Bad Path" {

                { Get-KeePassEntry -DatabaseProfileName SampleProfile -AsPlainText -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' } | Should Throw
            }

        }

        New-KPConfigurationFile -Force
    }

    Describe "Update-KeePassEntry - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Updates a KeePass Entry." {

            New-KPConfigurationFile -Force

            It "Example 1.1: Creates a New KeePass Entry - Invalid - No Profile" {
                { Update-KeePassEntry -KeePassEntry $( New-Object KeePassLib.PwEntry($true, $true))  -KeePassEntryGroupPath 'database' -Title 'test' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' }| Should Throw 'There are Currently No Database Configuration Profiles.'
            }

            ## Create Profile
            New-KeePassDatabaseConfiguration -DatabaseProfileName 'SampleProfile' -DatabasePath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -KeyPath "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.key"

            ## Reset Test DB
            Remove-Item -Path "$($PSScriptRoot)\Includes\PSKeePassTestDatabase.kdbx" -Force
            Copy-Item -Path "$($PSScriptRoot)\Includes\Backup\PSKeePassTestDatabase.kdbx" -Destination "$($PSScriptRoot)\Includes\"

            It "Example 1.2: Updates a KeePass Entry - Valid  - Properties" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test1' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -AsPlainText -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test1' } 
                Update-KeePassEntry -KeePassEntry $KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -title 'UpdateTest1' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -DatabaseProfileName 'SampleProfile' -Force | Should Be $null
            }

            It "Example 1.3: Updates a KeePass Entry - Valid  - Properties - Via Pipeline" {
                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test2' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null 
                Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -AsPlainText -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test2'} |
                Update-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -title 'UpdateTest2' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -DatabaseProfileName 'SampleProfile' -Force | Should Be $null
            }

            It "Example 1.4: Update a KeePass Entry - Valid - Properties - PassThru" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test3' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -AsPlainText -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test3' } 
                $UpdatePassThruResult = Update-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -KeePassEntry $KeePassEntry -title 'UpdateTest3' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -DatabaseProfileName 'SampleProfile' -PassThru -Force

                $UpdatePassThruResult | Should BeOfType KeePassLib.PwEntry
                $UpdatePassThruResult.Strings.ReadSafe('Title') | Should Be 'UpdateTest3'
                $UpdatePassThruResult.Strings.ReadSafe('UserName') | Should Be 'UpdateTestUser'
                $UpdatePassThruResult.Strings.ReadSafe('Notes') | Should Be 'UpdateTestNotes'
                $UpdatePassThruResult.Strings.ReadSafe('URL') | Should Be 'http://UpdateURL.Test.com'
            }

            It "Example 1.5: Update a KeePass Entry - Valid - Group & Properties - PassThru" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test4' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -AsPlainText -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test4' } 
                $UpdatePassThruResult = Update-KeePassEntry -KeePassEntry $KeePassEntry -title 'UpdateTest4' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -KeePassEntryGroupPath 'PSKeePassTestDatabase/General' -DatabaseProfileName 'SampleProfile' -PassThru -Force

                $UpdatePassThruResult | Should BeOfType KeePassLib.PwEntry
                $UpdatePassThruResult.ParentGroup.Name | Should Be 'General'
                $UpdatePassThruResult.Strings.ReadSafe('Title') | Should Be 'UpdateTest4'
                $UpdatePassThruResult.Strings.ReadSafe('UserName') | Should Be 'UpdateTestUser'
                $UpdatePassThruResult.Strings.ReadSafe('Notes') | Should Be 'UpdateTestNotes'
                $UpdatePassThruResult.Strings.ReadSafe('URL') | Should Be 'http://UpdateURL.Test.com'
            }

            It "Example 1.6: Update a KeePass Entry - Invalid - Group & Properties - PassThru - BadPath" {

                New-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -Title 'test4' -UserName 'testuser' -Notes 'testnotes' -URL 'http://url.test.com' -DatabaseProfileName 'SampleProfile' | Should Be $null
                $KeePassEntry = Get-KeePassEntry -KeePassEntryGroupPath 'PSKeePassTestDatabase' -AsPlainText -DatabaseProfileName 'SampleProfile' | Where-Object { $_.Title -eq 'test4' } 
                { Update-KeePassEntry -KeePassEntry $KeePassEntry -title 'UpdateTest4' -UserName 'UpdateTestUser' -Notes 'UpdateTestNotes' -URL 'http://UpdateURL.Test.com' -KeePassEntryGroupPath 'PSKeePassTestDatabase/BadPath' -DatabaseProfileName 'SampleProfile' -PassThru -Force } | Should Throw
            }
        }
        New-KPConfigurationFile -Force
    }

    <#
        Describe "Get-KPGroup - UnitTest" -Tag UnitTest {
            $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
            $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
            
            Context "Test 1: Gets a KeePass Group - FullPath" {
                
                It "Test 1a: Gets a KeePass Group Named General - FullPath" {
                    $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General'
                    $KeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                    $KeePassGroup.Name | Should Be 'General'
                    $KeePassGroup.Notes | Should Be ''
                    $KeePassGroup.ParentGroup.Name | Should be 'PSKeePassTestDatabase'
                }
                
                It "Test 1b: Gets multiple KeePass Groups - FullPath - TestSameName" {
                    $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestSameName'
                    $KeePassGroup.Count | Should Be 2
                    $KeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                    foreach ($_keepassGroup in $KeePassGroup)
                    {
                        $_keepassGroup.Name | Should be 'TestSameName'
                        $_keepassGroup.ParentGroup.Name | Should Be 'General' 
                        $_keepassGroup.GetFullPath("/",$false) | Should Be 'General/TestSameName'
                    }
                }
            }
            
            Context "Test 2: Gets a KeePass Group - GroupName" {
                
                It "Test 2a: Gets a KeePass Group Named Windows - GroupName" {
                    $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -GroupName 'Windows'
                    $KeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                    $KeePassGroup.Name | Should Be 'Windows'
                    $KeePassGroup.Notes | Should Be ''
                    $KeePassGroup.ParentGroup.Name | Should be 'PSKeePassTestDatabase'
                }
                
                IT "Test 2b: Gets multiple KeePass Groups - GroupName - TestSameName" {
                    $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -GroupName 'TestSameName'
                    $KeePassGroup.Count | Should Be 3
                    $KeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                    foreach ($_keepassGroup in $KeePassGroup)
                    {
                        $_keepassGroup.Name | Should Be 'TestSameName'
                    }
                    $KeePassGroup[0].ParentGroup.Name | Should be 'General'
                    $KeePassGroup[1].ParentGroup.Name | Should be 'General'
                    $KeePassGroup[2].ParentGroup.Name | Should be 'PSKeePassTestDatabase'
                }
            }
            Remove-KPConnection -KeePassConnection $KeePassConnection
        }
        
        Describe "Add-KPGroup - UnitTest" -Tag UnitTest {
            $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
            $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
            $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General'
            
            Context "Test 1: Add a KeePass Group" {
                
                It "Test 1a: Add a KeePass Group" {
                    Add-KPGroup -KeePassConnection $KeePassConnection -GroupName 'TestNewGroup' -KeePassParentGroup $KeePassGroup | Should Be $null
                    $NewKeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestNewGroup'
                    $NewKeePassGroup.Count | Should Be 1
                    $NewKeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                    $NewKeePassGroup.Name | Should Be 'TestNewGroup'
                    $NewKeePassGroup.ParentGroup.Name | Should Be 'General'
                    $NewKeePassGroup.GetFullPath("/", $false) | Should Be 'General/TestNewGroup'
                    ##Clean up
                    $NewKeePassGroup.ParentGroup.Groups.Remove($NewKeePassGroup) | Out-Null
                    $KeePassConnection.Save($null)
                }
                
            }
            Remove-KPConnection -KeePassConnection $KeePassConnection
        }
        
        Describe "Remove-KPGroup - UnitTest" -Tag UnitTest {
            $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
            $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
            
            Context "Test 1: Delete a KeePass Group" {
                $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestDeleteGroup'
                if(-not $KeePassGroup)
                {
                    $KeePassParentGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General'
                    Add-KPGroup -KeePassConnection $KeePassConnection -GroupName 'TestDeleteGroup' -KeePassParentGroup $KeePassParentGroup
                    $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestDeleteGroup'
                }
                
                It "Test 1a: Permenantly Deletes a KeePass Group" {
                    Remove-KPGroup -KeePassConnection $KeePassConnection -KeePassGroup $KeePassGroup -Force -NoRecycle | Should Be $null
                    Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestDeleteGroup' | Should Be $null
                }
            }
            
            Context "Test 2: Recycle a KeePass Group" {
                $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestRecycleGroup'
                if(-not $KeePassGroup)
                {
                    $KeePassParentGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General'
                    Add-KPGroup -KeePassConnection $KeePassConnection -GroupName 'TestRecycleGroup' -KeePassParentGroup $KeePassParentGroup
                    $KeePassGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestRecycleGroup'
                }
                
                It "Test 2a: Recycles a KeePass Group" {
                    Remove-KPGroup -KeePassConnection $KeePassConnection -KeePassGroup $KeePassGroup -Force | Should Be $null
                    $RecycledGroup = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'Recycle Bin/TestRecycleGroup'
                    $RecycledGroup | Should BeOfType 'KeePassLib.PwGroup'
                    $RecycledGroup.Name | Should Be 'TestRecycleGroup'
                    ##Clean Up
                    $RecycledGroup.ParentGroup.Groups.Remove($RecycledGroup) | Out-Null
                    $KeePassConnection.Save($null)
                }
            }
            
            Remove-KPConnection $KeePassConnection
        }
    #>
}