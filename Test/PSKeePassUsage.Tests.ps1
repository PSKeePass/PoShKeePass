Get-Module PSKeePass | Remove-Module
Import-Module "$PSScriptRoot\..\PSKeePass.psm1" -ErrorAction Stop

InModuleScope "PSKeePass" {

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