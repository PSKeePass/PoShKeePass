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
        }
        
        Context "Example 2: Mock with KeyFile" {
            
            It "Example 2: Get PSKeePass Credential - Valid" {
                $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.Key"           
                $KeePassCredential.MasterKey | Should Be ""
                $KeePassCredential.AuthenticationType | Should Be "Key"
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
            
            #Add Test for Password only
            #Add Test for KeyFile and Password.
        }
    }
    
    Describe "Remove-KeePassConnection - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Close an Open PSKeePass Database Connection" {
            
            It "Example: Closes an KeePass Database Connection" {
                $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassConnection = Get-KeePassConnection -KeePassCredential $KeePassCredential
                Remove-KeePassConnection -KeePassConnection $KeePassConnection | Should Be $null
            }
        }
    }
    
    Describe "Get-KeePassGroup - UnitTest" -Tag UnitTest {
        $KeePassCredential = Get-KeePassCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
        $KeePassConnection = Get-KeePassConnection -KeePassCredential $KeePassCredential
        
        Context "Test 1: Gets a KeePass Group - FullPath" {
            
            It "Test 1a: Gets a KeePass Group Named General - FullPath" {
                $KeePassGroup = Get-KeePassGroup -KeePassConnection $KeePassConnection -FullPath 'General'
                $KeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                $KeePassGroup.Name | Should Be 'General'
                $KeePassGroup.Notes | Should Be ''
                $KeePassGroup.ParentGroup.Name | Should be 'PSKeePassTestDatabase'
            }
            
            It "Test 1b: Gets multiple KeePass Groups - FullPath - TestSameName" {
                $KeePassGroup = Get-KeePassGroup -KeePassConnection $KeePassConnection -FullPath 'General/TestSameName'
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
                $KeePassGroup = Get-KeePassGroup -KeePassConnection $KeePassConnection -GroupName 'Windows'
                $KeePassGroup | Should BeOfType 'KeePassLib.PwGroup'
                $KeePassGroup.Name | Should Be 'Windows'
                $KeePassGroup.Notes | Should Be ''
                $KeePassGroup.ParentGroup.Name | Should be 'PSKeePassTestDatabase'
            }
            
            IT "Test 2b: Gets multiple KeePass Groups - GroupName - TestSameName" {
                $KeePassGroup = Get-KeePassGroup -KeePassConnection $KeePassConnection -GroupName 'TestSameName'
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
        
        Remove-KeePassConnection -KeePassConnection $KeePassConnection
    }
    
    
}