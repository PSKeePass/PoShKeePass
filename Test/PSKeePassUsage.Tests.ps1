Get-Module PSKeePass | Remove-Module
Import-Module "$PSScriptRoot\..\PSKeePass.psm1" -ErrorAction Stop

InModuleScope "PSKeePass" {
    
    Describe "Get-KPCredential - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Mock with Key File and Master Key" {
                    
            It "Example 1: Get PSKeePass Credential - Valid Files" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key" -MasterKey "AtestPassWord"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.Key"           
                $KeePassCredential.MasterKey | Should BeExactly "AtestPassWord"
                $KeePassCredential.AuthenticationType | Should Be "KeyAndMaster"
            }
        }
        
        Context "Example 2: Mock with KeyFile" {
            
            It "Example 2: Get PSKeePass Credential - Valid" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.Key"           
                $KeePassCredential.MasterKey | Should Be ""
                $KeePassCredential.AuthenticationType | Should Be "Key"
            }
        }
        
        Context "Example 3: Mock with MasterKey" {
            
            It "Example 3: Get PSKeePass Credential - Valid" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -MasterKey "AtestPassWord"
                $KeePassCredential.DatabaseFile | Should BeLike "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx"
                $KeePassCredential.KeyFile | Should Be ""         
                $KeePassCredential.MasterKey | Should BeExactly "AtestPassWord"
                $KeePassCredential.AuthenticationType | Should Be "Master"
            }
        }
    }
    
    Describe "Get-KPConnection - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Open with PSKeePass Credential Object - KeyFile" {
            
            It "Example 1: Get KeePass Database Connection with KeyFile - Valid" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
                $KeePassConnection | Should BeOfType 'KeePassLib.PwDatabase'
                $KeePassConnection.IsOpen | Should Be $true
                $KeePassConnection.Close() | Should Be $null
            }
            
            #Add Test for Password only
            #Add Test for KeyFile and Password.
        }
    }
    
    Describe "Remove-KPConnection - UnitTest" -Tag UnitTest {
        
        Context "Example 1: Close an Open PSKeePass Database Connection" {
            
            It "Example: Closes an KeePass Database Connection" {
                $KeePassCredential = Get-KPCredential -DatabaseFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.kdbx" -KeyFile "$PSScriptRoot\Includes\PSKeePassTestDatabase.key"
                $KeePassConnection = Get-KPConnection -KeePassCredential $KeePassCredential
                Remove-KPConnection -KeePassConnection $KeePassConnection | Should Be $null
            }
        }
    }
    
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
}