Get-Module PSKeePass | Remove-Module
Import-Module "$PSScriptRoot\..\PSKeePass.psm1" -ErrorAction Stop

InModuleScope "PSKeePass" {
    
    Describe "Get-KeePassCredential - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Mock with Key File and Master Key" {
                    
            It "Example 1: Get PSKeePass Credential - Valid Files" {
                $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key" -MasterKey "AtestPassWord"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.Key"           
                $KeePassCredential.MasterKey | Should BeExactly "AtestPassWord"
                $KeePassCredential.AuthenticationType | Should Be "KeyAndMaster"
            }
            
            It "Example 1: Get PSKeePass Credential - Invalid Database File" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdb" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key" -MasterKey "AtestPassWord" } | Should Throw
            }
            
            It "Example 1: Get PSKeePass Credential - Invalid Key File" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.ke" -MasterKey "AtestPassWord" } | Should Throw
            }
            
            It "Example 1: Get PSKeePass Credential - Invalid Database and Key Files" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdb" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.ke" -MasterKey "AtestPassWord" } | Should Throw
            }
        }
        
        Context "Example 2: Mock with KeyFile" {
            
            It "Example 2: Get PSKeePass Credential - Valid" {
                $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.Key"           
                $KeePassCredential.MasterKey | Should Be ""
                $KeePassCredential.AuthenticationType | Should Be "Key"
            }
            
            It "Example 2: Get PSKeePass Credential - Invalid Database File" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdb" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key" } | Should Throw
            }
            
            It "Example 2: Get PSKeePass Credential - Invalid Key File" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.ke" } | Should Throw
            }
            
            It "Example 2: Get PSKeePass Credential - Invalid Database and Key Files" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdb" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.ke" } | Should Throw
            }
        }
        
        Context "Example 3: Mock with MasterKey" {
            
            It "Example 3: Get PSKeePass Credential - Valid" {
                $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -MasterKey "AtestPassWord"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should Be ""         
                $KeePassCredential.MasterKey | Should BeExactly "AtestPassWord"
                $KeePassCredential.AuthenticationType | Should Be "Master"
            }
            
            It "Example 3: Get PSKeePass Credential - Invalid Database File" {
                { Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdb" -MasterKey "AtestPassWord" } | Should Throw
            }
        }
    }
    
    Describe "Get-KeePassConnection - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Open with PSKeePass Credential Object - KeyFile" {
            
            It "Example 1: Get KeePass Database Connection with KeyFile - Valid" {
                $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassConnection = Get-KeePassConnection -KeePassCredential $KeePassCredential
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.Close() | Should Be $null
            }
            
            It "Example 1: Get KeePass Database Connection with KeyFile - Invalid KeyFile" {
               $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\PSKeePassUsage.Tests.ps1"
               { Get-KeePassConnection -KeePassCredential $KeePassCredential -WarningAction SilentlyContinue } | Should Throw
            }
            
            It "Example 1: Get KeePass Database Connection with KeyFile - Invalid DatabaseFile" {
               $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\PSKeePassUsage.Tests.ps1" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
               { Get-KeePassConnection -KeePassCredential $KeePassCredential -WarningAction SilentlyContinue } | Should Throw
            }
            
            It "Example 1: Get KeePass Database Connection with KeyFile - Invalid DatabaseFile and KeyFile" {
               $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\PSKeePassUsage.Tests.ps1" -KeyFile "$PSScriptRoot\PSKeePassUsage.Tests.ps1"
               { Get-KeePassConnection -KeePassCredential $KeePassCredential -WarningAction SilentlyContinue } | Should Throw
            }
        }
    }
}