function New-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the newly created keepass database entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example creates a new keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 1, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 3, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 4, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 5, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 6, Mandatory = $false)]
        [Switch] $PassThru
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 7 -MasterKeyPosition 8 -PwIconPosition 9
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            $IconName = $PSBoundParameters['IconName']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        try
        {
            ## Get the keepass group
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath

            if(-not $KeePassGroup)
            {
                Write-Warning -Message ('[PROCESS] The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassEntryGroupPath)
                Throw 'The Specified KeePass Entry Group Path ({0}) does not exist.' - $KeePassEntryGroupPath
            }

            ## Set Default Icon if not specified.
            if(-not $IconName)
            {
                $IconName = 'Key'
            }
            ## Add the KeePass Entry
            Add-KpEntry -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroup -Title $Title -UserName $UserName -KeePassPassword $KeePassPassword -Notes $Notes -URL $URL -IconName $IconName -PassThru:$PassThru
        }
        catch
        {
            Throw $_
        }
    }
    end
    {
        ## Clean up keepass database connection
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function Get-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Funciton gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the forward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER AsPSCredential
            Output Entry as an PSCredential Object
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -AsPlainText

            This Example will return all enties in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General' -AsPlainText

            This Example will return all entries in plain text format from the General folder of the keepass database with the profile name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -Title test -AsPSCredential

            This Example will return one entry as PSCredential Object
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param
    (
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'AsPlainText')]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'AsPSCredential')]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'None')]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'AsPSCredential')]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'AsPlainText')]
        [String] $Title,

        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'AsPlainText')]
        [Switch] $AsPlainText,

        [Parameter(Position = 3, Mandatory = $false, ParameterSetName = 'AsPSCredential')]
        [Switch] $AsPSCredential
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 4 -MasterKeyPosition 5
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        if($KeePassEntryGroupPath)
        {
            ## Get All entries in the specified group
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath
            if(-not $KeePassGroup)
            {
                Write-Warning -Message ('[PROCESS] The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassEntryGroupPath)
                Throw 'The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassEntryGroupPath
            }
            if($Title)
            {
                $ResultEntries = Get-KpEntry -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroup -Title $Title
            }
            else
            {
                $ResultEntries = Get-KpEntry -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroup
            }
        }
        else
        {
            ## Get all entries in all groups.
            if($Title)
            {
                $ResultEntries = Get-KPEntry -KeePassConnection $KeePassConnectionObject -Title $Title
            }
            else
            {
                $ResultEntries = Get-KPEntry -KeePassConnection $KeePassConnectionObject
            }
        }
        Write-Verbose $PSCmdlet.ParameterSetName
        switch ($PSCmdlet.ParameterSetName)
        {
            "AsPlainText"
            {
                $ResultEntries | ConvertTo-KpPsObject
            }
            "AsPSCredential"
            {
                if ($ResultEntries.count -gt 1)
                {
                    Write-Warning "Multiple entries found, will only return first entry as PSCredential"
                }
                $secureString = ConvertTo-SecureString -String ($ResultEntries[0].Strings.ReadSafe('Password')) -AsPlainText -Force
                [string] $username = $ResultEntries[0].Strings.ReadSafe('UserName')
                if ($username.Length -eq 0)
                {
                    $Errorcode = 'ERROR: Cannot create credential, username is blank'
                    throw
                }
                New-Object System.Management.Automation.PSCredential($username, $secureString)
            }
            default
            {
                $ResultEntries
            }
        }
    }
    end
    {
        ## Clean up database connection
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function Update-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to update a KeePass Database Entry.
        .DESCRIPTION
            This function updates a KeePass Database Entry with basic properites available for specification.
        .PARAMETER KeePassEntry
            The KeePass Entry to be updated. Use the Get-KeePassEntry function to get this object.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the modified object.
        .PARAMETER Force
            Specify to Update the specified entry without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example updates a keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 4, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 6, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 7, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 8, Mandatory = $false)]
        [Switch] $Force

        ## Dynamic Param Position = 9
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 9 -MasterKeyPosition 10 -PwIconPosition 11
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            $IconName = $PSBoundParameters['IconName']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        ## Set Default Icon if not specified.
        if(-not $IconName)
        {
            $IconName = $KPEntry.IconId
        }

        if($Force -or $PSCmdlet.ShouldProcess("Title: $($KPEntry.Strings.ReadSafe('Title')), `n`tUserName: $($KPEntry.Strings.ReadSafe('UserName')), `n`tGroupPath: $($KPEntry.ParentGroup.GetFullPath('/', $true))."))
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath
            if(-not $KeePassGroup)
            {
                Write-Warning -Message ('[PROCESS] The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassEntryGroupPath)
                Throw 'The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassEntryGroupPath
            }
            Set-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KPEntry -Title $Title -UserName $UserName -KeePassPassword $KeePassPassword -Notes $Notes -URL $URL -KeePassGroup $KeePassGroup -IconName $IconName -PassThru:$PassThru -Force
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function Remove-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Entry.
        .DESCRIPTION
            This function removed a KeePass Database Entry.
        .PARAMETER KeePassEntry
            The KeePass Entry to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the entry and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassEntry -KeePassEntry $KeePassEntryObject

            This example removed the specified kee pass entry.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 1, Mandatory = $false)]
        [Switch] $NoRecycle,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $Force
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 3 -MasterKeyPosition 4
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }
        $EntryDisplayName = '{0}/{1}' -f $KPEntry.ParentGroup.GetFullPath('/', $true), $KPEntry.Strings.ReadSafe('Title')
        if($Force -or $PSCmdlet.ShouldProcess($EntryDisplayName))
        {
            if($NoRecycle)
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Do you want to continue to Permanently Delete this Entry: $EntryDisplayName)?"))
                {
                    Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KPEntry -NoRecycle -Confirm:$false -Force
                }
            }
            else
            {
                Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KPEntry -Confirm:$false -Force
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function New-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER KeePassGroupName
            Specify the Name of the new KeePass Group.
        .PARAMETER PassThru
            Specify to return the new group object.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .EXAMPLE
            PS> New-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts' -KeePassGroupName 'TestGroup'

            This Example Creates a Group Called 'TestGroup' in the Group Path 'General/TestAccounts'
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupParentPath,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupName,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $PassThru
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 3 -MasterKeyPosition 4 -PwIconPosition 5
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            $IconName = $PSBoundParameters['IconName']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        ## Get the keepass group
        $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupParentPath
        if(-not $KeePassParentGroup)
        {
            Write-Warning -Message ('[PROCESS] The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassGroupParentPath)
            Throw 'The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassGroupParentPath
        }

        ## Set Default Icon if not specified.
        if(-not $IconName)
        {
            $IconName = 'Folder'
        }
        ## Add the KeePass Group
        Add-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassParentGroup $KeePassParentGroup -GroupName $KeePassGroupName -IconName $IconName -PassThru:$PassThru
    }
    end
    {
        ## Clean up keepass database connection
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function Get-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Funciton gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -AsPlainText

            This Example will return all groups in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -KeePassGroupPath 'General' -AsPlainText

            This Example will return all groups in plain text format from the General folder of the keepass database with the profile name TEST.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupPath,

        [Parameter(Position = 1, Mandatory = $false)]
        [Switch] $AsPlainText
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 2 -MasterKeyPosition 3
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        if($KeePassGroupPath)
        {
            ## Get All entries in the specified group
            $ResultEntries = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupPath
        }
        else
        {
            ## Get all entries in all groups.
            $ResultEntries = Get-KPGroup -KeePassConnection $KeePassConnectionObject
        }

        ## return results in plain text or not.
        if($AsPlainText)
        {
            $ResultEntries | ConvertTo-KpPsObject
        }
        else
        {
            $ResultEntries
        }
    }
    end
    {
        ## Clean up database connection
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function Update-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to update a KeePass Database Group.
        .DESCRIPTION
            This function updates a KeePass Database Group.
        .PARAMETER KeePassGroup
            The KeePass Group to be updated. Use the Get-KeePassGroup function to get this object.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish move the specified group to a different parent group.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER GroupName
            Specify the GroupName to change the specified group to.
        .PARAMETER PassThru
            Specify to return the updated keepass group object.
        .PARAMETER Force
            Specify to Update the specified group without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .EXAMPLE
            PS> Update-KeePassGroup -DatabaseProfileName TEST -KeePassGroup $KeePassGroupObject -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves the specified KeePassGroup to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves group specified via the pipeline to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -GroupName 'DevGroup'

            This Example renames the group specified via the pipeline to 'DevGroup'
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 1, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassParentGroupPath,

        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 3, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 4, Mandatory = $false)]
        [Switch] $Force
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 5 -MasterKeyPosition 6 -PwIconPosition 7
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            $IconName = $PSBoundParameters['IconName']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        if($KeePassParentGroupPath)
        {
            $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassParentGroupPath
            if(-not $KeePassParentGroup)
            {
                Write-Warning -Message ('[PROCESS] The Specified KeePass Parent Group Path ({0}) does not exist.' -f $KeePassGroupParentPath)
                Throw 'The Specified KeePass Parent Group Path ({0}) does not exist.' -f $KeePassGroupParentPath
            }
        }

        if($KeePassGroup.GetType().Name -eq 'PwGroup')
        {
            $KeePassGroupFullPath = '{0}' -f $KeePassGroup.GetFullPath('/', $true)
        }
        else
        {
            $KeePassGroupFullPath = '{0}/{1}' -f $KeePassGroup.FullPath, $KeePassGroup.Name
        }
        ## Confirm
        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroupFullPath))
        {
            $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupFullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime}

            if($KeePassGroupObject.Count -gt 1)
            {
                Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Update.'
                Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups' -f $KeePassGroupObject.Count)
                Throw 'Found more than one group with the same path, name and creation time.'
            }

            ## Set Default Icon if not specified.
            if(-not $IconName)
            {
                $IconName = $KeePassGroupObject.IconId
            }

            if($KeePassParentGroup)
            {

                Set-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -KeePassParentGroup $KeePassParentGroup -GroupName $GroupName -IconName $IconName -PassThru:$PassThru -Confirm:$false -Force
            }
            else
            {
                Set-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -GroupName $GroupName -IconName $IconName -PassThru:$PassThru -Confirm:$false -Force
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function Remove-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Group.
        .DESCRIPTION
            This function removed a KeePass Database Group.
        .PARAMETER KeePassGroup
            The KeePass Group to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml.
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the Group and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the Group.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassGroup -KeePassGroup $KeePassGroupObject

            This example removed the specified keepass Group.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 1, Mandatory = $false)]
        [Switch] $NoRecycle,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $Force
    )
    dynamicparam
    {
        Get-KPDynamicParameters -DBProfilePosition 3 -MasterKeyPosition 4
    }
    begin
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters['DatabaseProfileName']
            $MasterKey = $PSBoundParameters['MasterKey']
            ## Open the database
            $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
            ## remove any sensitive data
            if($MasterKey){Remove-Variable -Name MasterKey}
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Write-Warning -Message '[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        if($KeePassGroup.GetType().Name -eq 'PwGroup')
        {
            $KeePassGroupFullPath = '{0}' -f $KeePassGroup.GetFullPath('/', $true)
        }
        else
        {
            $KeePassGroupFullPath = '{0}/{1}' -f $KeePassGroup.FullPath, $KeePassGroup.Name
        }
        $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupFullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime}

        if(-not $KeePassGroupObject)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Group does not exist.'
            Throw 'The Specified KeePass Group does not exist.'
        }

        if($KeePassGroupObject.Count -gt 1)
        {
            Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Removal.'
            Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups.' -f $KeePassGroupObject.Count)
            Throw 'Found more than one group with the same path, name and creation time. Stoping Removal.'
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroupFullPath))
        {
            if(-not $NoRecycle)
            {
                Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -Confirm:$false -Force
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Remove this Group permanetly: $KeePassGroupFullPath?"))
                {
                    Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -NoRecycle:$NoRecycle -Confirm:$false -Force
                }
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

function New-KeePassPassword
{
    <#
        .SYNOPSIS
            This Function will Generate a New Password.
        .DESCRIPTION
            This Function will Generate a New Password with the Specified rules using the KeePass-
            Password Generator.

            This Contains the Majority of the Options including the advanced options that the KeePass-
            UI provides in its "PasswordGenerator Form".

            Currently this function does not support the use of previously saved/created Password Profiles-
            aka KeePassLib.Security.PasswordGenerator.PwProfile. Nore does it support Saving a New Profile.

            This Simply Applies the Rules specified and generates a new password that is returned in the form-
            of a KeePassLib.Security.ProtectedString.
        .EXAMPLE
            PS> New-KeePassPassword

            This Example will generate a Password using the Default KeePass Password Profile.
            Which is is -UpperCase -LowerCase -Digites -Length 20
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -Length 20

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -Length 20 -SaveAs 'Basic Password'

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9.
            Then it will save it as a password profile with the bane 'Basic Password' for future reuse.
        .EXAMPLE
            PS> New-KeePassPassword -PasswordProfileName 'Basic Password'

            This Example will generate a password using the password profile name Basic Password.
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -ExcludeCharacters '"' -Length 20

            This Example will generate a Password with the Specified Options and Exclude the Double Quote Character
        .PARAMETER UpperCase
            If Specified it will add UpperCase Letters to the character set used to generate the password.
        .PARAMETER LowerCase
            If Specified it will add LowerCase Letters to the character set used to generate the password.
        .PARAMETER Digits
            If Specified it will add Digits to the character set used to generate the password.
        .PARAMETER SpecialCharacters
            If Specified it will add Special Characters '!"#$%&''*+,./:;=?@\^`|~' to the character set used to generate the password.
        .PARAMETER Minus
            If Specified it will add the Minus Symbol '-' to the character set used to generate the password.
        .PARAMETER UnderScore
            If Specified it will add the UnderScore Symbol '_' to the character set used to generate the password.
        .PARAMETER Space
            If Specified it will add the Space Character ' ' to the character set used to generate the password.
        .PARAMETER Brackets
            If Specified it will add Bracket Characters '()<>[]{}' to the character set used to generate the password.
        .PARAMETER ExcludeLookAlike
            If Specified it will exclude Characters that Look Similar from the character set used to generate the password.
        .PARAMETER NoRepeatingCharacters
            If Specified it will only allow Characters exist once in the password that is returned.
        .PARAMETER ExcludeCharacters
            This will take a list of characters to Exclude, and remove them from the character set used to generate the password.
        .PARAMETER Length
            This will specify the length of the resulting password. If not used it will use KeePass's Default Password Profile
            Length Value which I believe is 20.
        .PARAMETER SaveAS
            Specify the name in which you wish to save the password configuration as.
            This will save all specified settings the KeePassConfiguration.xml file, which can then be specifed later when genreating a password to match the same settings.
        .PARAMETER PasswordProfileName
            *Specify this parameter to use a previously saved password profile to genreate a password.
            *Note:
                *This supports Tab completion as it will get all saved profiles. (ie its a dynamic parameter.)
                *Since it is a dynamic parameter it will only show up if there are already profiles to use.
        .INPUTS
            String
            Switch
        .OUTPUTS
            KeePassLib.Security.ProtectedString
    #>
    [CmdletBinding(DefaultParameterSetName = 'NoProfile')]
    param
    (
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UpperCase,
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $LowerCase,
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Digits,
        [Parameter(Position = 3, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $SpecialCharacters,
        [Parameter(Position = 4, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Minus,
        [Parameter(Position = 5, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UnderScore,
        [Parameter(Position = 6, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Space,
        [Parameter(Position = 7, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Brackets,
        [Parameter(Position = 8, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $ExcludeLookALike,
        [Parameter(Position = 9, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $NoRepeatingCharacters,
        [Parameter(Position = 10, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $ExcludeCharacters,
        [Parameter(Position = 11, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [Int] $Length,
        [Parameter(Position = 12, Mandatory = $false, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $SaveAs
    )
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $PasswordProfileList = (Get-KPPasswordProfile).Name
        if($PasswordProfileList)
        {
            $ParameterName = 'PasswordProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            ###ParameterSet Host
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 0
            $ParameterAttribute.ParameterSetName = 'Profile'
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($PasswordProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ##Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ##Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
            return $RuntimeParameterDictionary
        }
    }
    begin
    {
        if($PasswordProfileList)
        {
            $PasswordProfileName = $PSBoundParameters[$ParameterName]
        }
    }
    process
    {
        ## Create New Password Profile.
        $PassProfile = New-Object KeePassLib.Cryptography.PasswordGenerator.PwProfile

        if($PSCmdlet.ParameterSetName -eq 'NoProfile')
        {
            $NewProfileObject = '' | Select-Object ProfileName, CharacterSet, ExcludeLookAlike, NoRepeatingCharacters, ExcludeCharacters, Length
            if($PSBoundParameters.Count -gt 0)
            {
                $PassProfile.CharSet = New-Object KeePassLib.Cryptography.PasswordGenerator.PwCharSet
                ## Build Profile With Options.
                if($UpperCase)
                {
                    $NewProfileObject.CharacterSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                }

                if($LowerCase)
                {
                    $NewProfileObject.CharacterSet += 'abcdefghijklmnopqrstuvwxyz'
                }

                if($Digits)
                {
                    $NewProfileObject.CharacterSet += '0123456789'
                }

                if($SpecialCharacters)
                {
                    $NewProfileObject.CharacterSet += '!"#$%&''*+,./:;=?@\^`|~'
                }

                if($Minus)
                {
                    $NewProfileObject.CharacterSet += '-'
                }

                if($UnderScore)
                {
                    $NewProfileObject.CharacterSet += '_'
                }

                if($Space)
                {
                    $NewProfileObject.CharacterSet += ' '
                }

                if($Brackets)
                {
                    $NewProfileObject.CharacterSet += '[]{}()<>'
                }

                if($ExcludeLookALike)
                {
                    $NewProfileObject.ExcludeLookAlike = $true
                }
                else
                {
                    $NewProfileObject.ExcludeLookAlike = $false
                }

                if($NoRepeatingCharacters)
                {
                    $NewProfileObject.NoRepeatingCharacters = $true
                }
                else
                {
                    $NewProfileObject.NoRepeatingCharacters = $false
                }

                if($ExcludeCharacters)
                {
                    $NewProfileObject.ExcludeCharacters = $ExcludeCharacters
                }
                else
                {
                    $NewProfileObject.ExcludeCharacters = ''
                }

                if($Length)
                {
                    $NewProfileObject.Length = $Length
                }
                else
                {
                    $NewProfileObject.Length = '20'
                }

                $PassProfile.CharSet.Add($NewProfileObject.CharacterSet)
                $PassProfile.ExcludeLookAlike = $NewProfileObject.ExlcudeLookAlike
                $PassProfile.NoRepeatingCharacters = $NewProfileObject.NoRepeatingCharacters
                $PassProfile.ExcludeCharacters = $NewProfileObject.ExcludeCharacters
                $PassProfile.Length = $NewProfileObject.Length
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Profile')
        {
            $PasswordProfileObject = Get-KPPasswordProfile -PasswordProfileName $PasswordProfileName
            $PassProfile.CharSet.Add($PasswordProfileObject.CharacterSet)
            $PassProfile.ExcludeLookAlike = if($PasswordProfileObject.ExlcudeLookAlike -eq 'True'){$true}else{$false}
            $PassProfile.NoRepeatingCharacters = if($PasswordProfileObject.NoRepeatingCharacters -eq 'True'){$true}else{$false}
            $PassProfile.ExcludeCharacters = $PasswordProfileObject.ExcludeCharacters
            $PassProfile.Length = $PasswordProfileObject.Length
        }

        ## Create Pass Generator Profile Pool.
        $GenPassPool = New-Object KeePassLib.Cryptography.PasswordGenerator.CustomPwGeneratorPool
        ## Create Out Parameter aka [rel] param.
        [KeePassLib.Security.ProtectedString]$PSOut = New-Object KeePassLib.Security.ProtectedString
        ## Generate Password.
        $ResultMessage = [KeePassLib.Cryptography.PasswordGenerator.PwGenerator]::Generate([ref] $PSOut, $PassProfile, $null, $GenPassPool)
        ## Check if Password Generation was successful
        if($ResultMessage -ne 'Success')
        {
            Write-Warning -Message '[PROCESS] Failure while attempting to generate a password with the specified settings or profile.'
            Write-Warning -Message ('[PROCESS] Password Generation Failed with the Result Text: {0}.' -f $ResultMessage)
            if($ResultMessage -eq 'TooFewCharacters')
            {
                Write-Warning -Message ('[PROCESS] Result Text {0}, typically means that you specified a length that is longer than the possible generated outcome.' -f $ResultMessage)
                $ExcludeCharacterCount = if($PassProfile.ExcludeCharacters){($PassProfile.ExcludeCharacters -split ',').Count}else{0}
                if($PassProfile.NoRepeatingCharacters -and $PassProfile.Length -gt ($PassProfile.CharSet.Size - $ExcludeCharacterCount))
                {
                    Write-Warning -Message "[PROCESS] Checked for the invalid specification. `n`tSpecified Length: $($PassProfile.Length). `n`tCharacterSet Count: $($PassProfile.CharSet.Size). `n`tNo Repeating Characters is set to: $($PassProfile.NoRepeatingCharacters). `n`tExclude Character Count: $ExcludeCharacterCount."
                    Write-Warning -Message '[PROCESS] Specify More characters, shorten the length, remove the no repeating characters option, or removed excluded characters.'
                }
            }

            Throw 'Unabled to generate a password with the specified options.'
        }
        else
        {
            if($SaveAs)
            {
                $NewProfileObject.ProfileName = $SaveAs
                New-KPPasswordProfile -KeePassPasswordObject $NewProfileObject
            }
        }
        try
        {
            $PSOut
        }
        catch
        {
            Write-Warning -Message '[PROCESS] An exception occured while trying to convert the KeePassLib.Securtiy.ProtectedString to a SecureString.'
            Write-Warning -Message ('[PROCESS] Exception Message: {0}' -f $_.Exception.Message)
            Throw $_
        }
    }
    end
    {
        ## Clean up out varaible
        if($PSOut){Remove-Variable -Name PSOUT}
    }
}

function New-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Create or Add a new KeePass Database Configuration Profile to the KeePassConfiguration.xml
        .DESCRIPTION
            The Profile Created will be accessible from the core functions Get,Update,New,Remove KeePassEntry and ect.
            The Profile stores database configuration for opening and authenticating to a keepass database.
            Using the configuration allows for speedier authentication and less complex commands.
        .PARAMETER DatabaseProfileName
            Specify the Name of the new Database Configuration Profile.
        .PARAMETER DatabasePath
            Specify the Path to the database (.kdbx) file.
        .PARAMETER KeyPath
            Specify the Path to the database (.key) key file if there is one.
        .PARAMETER UseNetworkAccount
            Specify this flag if the database uses NetworkAccount Authentication.
        .PARAMETER UseMasterKey
            Specify this flag if the database uses a Master Key Password for Authentication.
        .PARAMETER PassThru
            Specify to return the new database configuration profile object.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -KeyPath 'c:\users\username\documents\personal.key' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Key File and Uses NetworkAccount.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Uses NetworkAccount.
        .NOTES
            1. Currently all authentication combinations are supported except keyfile, masterkey password, and network authentication together.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Master')]
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Network')]
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $DatabasePath,

        [Parameter(Position = 2, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Key')]
        [Parameter(Position = 2, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 3, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Key')]
        [Parameter(Position = 3, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Master')]
        [Parameter(Position = 3, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 4, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Master')]
        [Parameter(Position = 4, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'KeyAndMaster')]
        [Switch] $UseMasterKey,

        [Parameter(Position = 5, Mandatory = $false)]
        [Switch] $PassThru
    )
    begin
    {
        if($PSCmdlet.ParameterSetName -eq 'Network' -and -not $UseNetworkAccount)
        {
            Write-Warning -Message '[BEGIN] Please Specify a valid Credential Combination.'
            Write-Warning -Message '[BEGIN] You can not have a only a database file with no authentication options.'
            Throw 'Please Specify a valid Credential Combination.'
        }
    }
    process
    {
        if (-not (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist. One will be generated now.'
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if($CheckIfProfileExists)
        {
            Write-Warning -Message ('[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName)
            Throw '[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName
        }
        else
        {
            try
            {
                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load("$PSScriptRoot\KeePassConfiguration.xml")
                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $DatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null

                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element', 'DatabasePath', '')
                $DatabasePathNode.InnerText = $DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null

                $KeyPathNode = $XML.CreateNode('element', 'KeyPath', '')
                $KeyPathNode.InnerText = $KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null

                $UseNetworkAccountNode = $XML.CreateNode('element', 'UseNetworkAccount', '')
                $UseNetworkAccountNode.InnerText = $UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null

                $UseMasterKeyNode = $XML.CreateNode('element', 'UseMasterKey', '')
                $UseMasterKeyNode.InnerText = $UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null

                $AuthenticationTypeNode = $XML.CreateNode('element', 'AuthenticationType', '')
                $AuthenticationTypeNode.InnerText = $PSCmdlet.ParameterSetName
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').AppendChild($DatabaseProfile) | Out-Null

                $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")

                if($PassThru)
                {
                    Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
                }
            }
            catch [Exception]
            {
                Write-Warning -Message ('[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ({0}) to the configuration file.' -f $DatabaseProfileName)
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}

function Get-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .DESCRIPTION
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to lookup.
            Note this is a Dynamic Parameter and will only be available if there are profiles in the KeePassConfiguration.xml.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration

            This Example will return all Database Configuration Profiles if any.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example returns the Database Configuration Profile with the name Personal.
        .INPUTS
            Strings
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName
    )
    process
    {
        if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load("$PSScriptRoot\KeePassConfiguration.xml")
            if($DatabaseProfileName)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -ilike $DatabaseProfileName }
            }
            else
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile
            }

            foreach($ProfileResult in $ProfileResults)
            {
                $UseNetworkAccount = if($ProfileResult.UseNetworkAccount -eq 'True'){$true}else{$false}
                $UseMasterKey = if($ProfileResult.UseMasterKey -eq 'True'){$true}else{$false}

                $ProfileObject = New-Object -TypeName PSObject
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'Name' -Value $ProfileResult.Name
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'DatabasePath' -Value $ProfileResult.DatabasePath
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'KeyPath' -Value $ProfileResult.KeyPath
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'UseMasterKey' -Value $UseMasterKey
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'UseNetworkAccount' -Value $UseNetworkAccount
                $ProfileObject | Add-Member -MemberType NoteProperty -Name 'AuthenticationType' -Value $ProfileResult.AuthenticationType
                $ProfileObject
            }
        }
        else
        {
            Write-Warning 'No KeePass Configuration has been created.'
        }
    }
}

function Remove-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Configuration Profile.
        .DESCRIPTION
            This function allows a specified database configuration profile to be removed from the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to be deleted.
            Note this is a Dynamic Parameter and will only be available if there are profiles to be removed.
        .EXAMPLE
            PS> Remove-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example will remove the database configuration profile 'Personal' from the KeePassConfiguration.xml file.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        if($DatabaseProfileList)
        {
            $ParameterName = 'DatabaseProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            ###ParameterSet Host
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 0
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($DatabaseProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ##Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ##Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
            return $RuntimeParameterDictionary
        }
    }
    begin
    {
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters[$ParameterName]
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Database Configuration Profiles.'
            Throw 'There are Currently No Database Configuration Profiles.'
        }
    }
    process
    {
        if (-not (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist.'
            Throw 'A KeePass Configuration File does not exist.'
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName

            if($CheckIfProfileExists)
            {
                if($PSCmdlet.ShouldProcess($DatabaseProfileName))
                {
                    try
                    {
                        [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                        $XML.Load("$PSScriptRoot\KeePassConfiguration.xml")
                        $XML.Settings.DatabaseProfiles.Profile  | Where-Object { $_.Name -eq $DatabaseProfileName } | ForEach-Object { $xml.Settings.DatabaseProfiles.RemoveChild($_) } | Out-Null
                        $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")
                    }
                    catch [exception]
                    {
                        Write-Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Database Configuration Profile ({0}).' -f $DatabaseProfileName)
                        Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                        Throw $_
                    }
                }
            }
            else
            {
                Write-Warning -Message ('[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: {0}.' -f $DatabaseProfileName)
                Throw '[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: {0}.' -f $DatabaseProfileName
            }
        }

    }
}

function New-KeePassDatabase
{
    <#
        .SYNOPSIS
            Function to create a keepass database.
        .DESCRIPTION
            This function creates a new keepass database
        .PARAMETER DatabasePath
            Path to the Keepass database (.kdbx file)
        .PARAMETER KeyPath
            Not yet implemented
        .PARAMETER UseNetworkAccount
            Specify of you want the database to use windows authentication
        .PARAMETER MasterKey
            The masterkey that provides access to the database
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabasePath,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 2, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Key')]
        [Parameter(Position = 2, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Master')]
        [Parameter(Position = 2, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 3, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Master')]
        [Parameter(Position = 3, Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'KeyAndMaster')]
        [PSCredential] $MasterKey
    )

    begin
    {
        if ($KeyPath)
        {
            throw "KeyPath is not implemented yet"
        }
    }
    process
    {
        try
        {
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }
        catch
        {
            Import-KPLibrary
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }

        ## Create KP CompositeKey Object
        $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

        if($MasterKey)
        {
            $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($MasterKey.GetNetworkCredential().Password)
            $CompositeKey.AddUserKey($KcpPassword)
        }

        #if masterkey is specified, it should
        if($UseNetworkAccount)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
        }

        $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
        $IOInfo.Path = $DatabasePath

        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

        $DatabaseObject.New($IOInfo, $CompositeKey) | Out-Null
        $DatabaseObject.Save($IStatusLogger)
    }
}

<#
# Internals
# *These functions below support all of the functions above.
# *Their intended purpose is to be used for advanced scripting.
#>
function New-KPConfigurationFile
{
    <#
        .SYNOPSIS
            This Internal Function Creates the KeePassConfiguration.xml file.
        .DESCRIPTION
            This Internal Function Creates the KeePassConfiguration.xml file.
            This File is used to store database configuration for file locations, authentication settings and password profiles.
        .PARAMETER Force
            Specify this parameter to forcefully overwrite the existing config with a new fresh config.
        .EXAMPLE
            PS> New-KPConfigurationFile

            This Example will create a new KeePassConfiguration.xml file.
        .NOTES
            Internal Function.
        .INPUTS
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false)]
        [Switch] $Force
    )
    process
    {
        if ((Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml) -and -not $Force)
        {
            Write-Warning -Message '[PROCESS] A KeePass Configuration File already exists. Please rerun with -force to overwrite the existing configuration.'
            Throw 'A KeePass Configuration File already exists.'
        }
        else
        {
            try
            {
                $Path = '{0}\KeePassConfiguration.xml' -f $PSScriptRoot

                $XML = New-Object System.Xml.XmlTextWriter($Path, $null)
                $XML.Formatting = 'Indented'
                $XML.Indentation = 1
                $XML.IndentChar = "`t"
                $XML.WriteStartDocument()
                $XML.WriteProcessingInstruction('xml-stylesheet', "type='text/xsl' href='style.xsl'")
                $XML.WriteStartElement('Settings')
                $XML.WriteStartElement('DatabaseProfiles')
                $XML.WriteEndElement()
                $XML.WriteStartElement("PasswordProfiles")
                $XML.WriteEndElement()
                $XML.WriteEndElement()
                $XML.WriteEndDocument()
                $xml.Flush()
                $xml.Close()
            }
            catch
            {
                Write-Warning -Message '[PROCESS] An exception occured while trying to create a new keepass configuration file.'
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }

        }
    }
}

function Restore-KPConfigurationFile
{
    <#
        .SYNOPSIS
            Restore Config file from previous version
        .DESCRIPTION
            Restore Config file from previous version
        .PARAMETER
        .EXAMPLE
        .NOTES
        .INPUTS
        .OUTPUTS
    #>
    [CmdletBinding()]
    param
    (

    )
    process
    {
        $ReturnStatus = $false
        $Path = Resolve-Path -Path ('{0}\..' -f $PSScriptRoot)
        Write-Verbose -Message ('[PROCESS] Checking if there is a previous KeePassConfiguration.xml file to be loaded from: {0}.' -f $Path.Path )
        $PreviousVerision = ((Get-ChildItem $Path.Path).Name | Sort-Object -Descending | Select-Object -First 2)[1]
        Write-Verbose -Message ('PreviousVersion: {0}.' -f $PreviousVersion)
        $PreviousVerisionConfigurationFile = Resolve-Path -Path ('{0}\..\{1}\KeePassConfiguration.xml' -f $PSScriptRoot, $PreviousVerision) -ErrorAction SilentlyContinue -ErrorVariable GetPreviousConfigurationFileError
        if(-not $GetPreviousConfigurationFileError -and $PreviousVerision)
        {
            Write-Verbose -Message ('[PROCESS] Copying last Configuration file from the previous version ({0}).' -f $PreviousVerision)
            Copy-Item -Path $PreviousVerisionConfigurationFile -Destination "$PSScriptRoot" -ErrorAction SilentlyContinue -ErrorVariable RestorePreviousConfigurationFileError
            if($RestorePreviousConfigurationFileError)
            {
                Write-Warning -Message '[PROCESS] Unable to restore previous KeePassConfiguration.xml file. You will need to copy your previous file from your previous module version folder or create a new one.'
            }
            else
            {
                $ReturnStatus = $true
            }
        }

        return $ReturnStatus
    }
}

function New-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to save a password profile to the KeePassConfiguration.xml file.
        .DESCRIPTION
            This funciton will save a password profile to the config file.
            This is an internal function and is used in the -saveas option of the New-KeePassPassword function.
        .PARAMETER KeePassPasswordObject
            Specify the KeePass Password Profile Object to be saved to the config file.
        .EXAMPLE
            PS> New-KPPasswordProfile -KeePassPasswordObject $NewPasswordProfile

            This Example adds the $NewPasswordProfile object to the KeePassConfiguration.xml file.
        .NOTES
            Internal Funciton
        .INPUTS
            PSObject
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $KeePassPasswordObject
    )
    process
    {
        if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
        {
            $CheckIfExists = Get-KPPasswordProfile -PasswordProfileName $KeePassPasswordObject.ProfileName
            if($CheckIfExists)
            {
                Write-Warning -Message ('[PROCESS] A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName)
                Throw 'A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName
            }

            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load("$PSScriptRoot\KeePassConfiguration.xml")
            ## Create New Profile Element with Name of the new profile
            $PasswordProfile = $XML.CreateElement('Profile')
            $PasswordProfileAtribute = $XML.CreateAttribute('Name')
            $PasswordProfileAtribute.Value = $KeePassPasswordObject.ProfileName
            $PasswordProfile.Attributes.Append($PasswordProfileAtribute) | Out-Null

            ## Build and Add Element Nodes
            $CharacterSetNode = $XML.CreateNode('element', 'CharacterSet', '')
            $CharacterSetNode.InnerText = $KeePassPasswordObject.CharacterSet
            $PasswordProfile.AppendChild($CharacterSetNode) | Out-Null

            $ExcludeLookAlikeNode = $XML.CreateNode('element', 'ExcludeLookAlike', '')
            $ExcludeLookAlikeNode.InnerText = $KeePassPasswordObject.ExcludeLookAlike
            $PasswordProfile.AppendChild($ExcludeLookAlikeNode) | Out-Null

            $NoRepeatingCharactersNode = $XML.CreateNode('element', 'NoRepeatingCharacters', '')
            $NoRepeatingCharactersNode.InnerText = $KeePassPasswordObject.NoRepeatingCharacters
            $PasswordProfile.AppendChild($NoRepeatingCharactersNode) | Out-Null

            $ExcludeCharactersNode = $XML.CreateNode('element', 'ExcludeCharacters', '')
            $ExcludeCharactersNode.InnerText = $KeePassPasswordObject.ExcludeCharacters
            $PasswordProfile.AppendChild($ExcludeCharactersNode) | Out-Null

            $LengthNode = $XML.CreateNode('element', 'Length', '')
            $LengthNode.InnerText = $KeePassPasswordObject.Length
            $PasswordProfile.AppendChild($LengthNode) | Out-Null

            $XML.SelectSingleNode('/Settings/PasswordProfiles').AppendChild($PasswordProfile) | Out-Null

            $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")
        }
        else
        {
            Write-Output 'No KeePass Configuration has been created. You can create one with Set-KeePassConfiguration'
        }
    }

}

function Get-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to Retreive All or a Specified Password Profile.
        .DESCRIPTION
            Function to Retreive All or a Specified Password Profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile Name to Retreive.
        .EXAMPLE
            PS> Get-KPPasswordProfile

            Returns all Password Profile definitions if any.
        .NOTES
            Internal Funciton.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    process
    {
        if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load("$PSScriptRoot\KeePassConfiguration.xml")
            if($PasswordProfileName)
            {
                $XML.Settings.PasswordProfiles.Profile | Where-Object { $_.Name -ilike $PasswordProfileName}
            }
            else
            {
                $XML.Settings.PasswordProfiles.Profile
            }
        }
        else
        {
            Write-Verbose 'No KeePass Configuration has been created.'
        }
    }
}

function Remove-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to remove a specifed Password Profile.
        .DESCRIPTION
            Removes a specified password profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile to be delete from the config file.
            Note this is a Dynamic Parameter.
        .EXAMPLE
            PS> Remove-KPPasswordProfile -PasswordProfileName 'Personal'

            This example remove the password profile with the name 'Personal'
        .NOTES
            Internal Funciton.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    dynamicparam
    {
        ## Create and Define Validate Set Attribute
        $PasswordProfileList = (Get-KPPasswordProfile).Name
        if($PasswordProfileList)
        {
            $ParameterName = 'PasswordProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 0
            $ParameterAttribute.ValueFromPipelineByPropertyName = $true
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($PasswordProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ## Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ## Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
            return $RuntimeParameterDictionary
        }
    }
    begin
    {
        if($PasswordProfileList)
        {
            $PasswordProfileName = $PSBoundParameters[$ParameterName]
        }
        else
        {
            Write-Warning -Message '[BEGIN] There are Currently No Password Profiles.'
            Throw 'There are Currently No Password Profiles.'
        }
    }
    process
    {
        if (-not (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist.'
        }
        else
        {
            if($PSCmdlet.ShouldProcess($PasswordProfileName))
            {
                try
                {
                    [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                    $XML.Load("$PSScriptRoot\KeePassConfiguration.xml")
                    $XML.Settings.PasswordProfiles.Profile  | Where-Object { $_.Name -eq $PasswordProfileName } | ForEach-Object { $xml.Settings.PasswordProfiles.RemoveChild($_) } | Out-Null
                    $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")
                }
                catch [exception]
                {
                    Write-Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Password Profile ({0}).' -f $PasswordProfileName)
                    Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                    Throw $_
                }
            }
        }
    }
}

function New-KPConnection
{
    <#
        .SYNOPSIS
            Creates an open connection to a Keepass database
        .DESCRIPTION
            Creates an open connection to a Keepass database using all available authentication methods
        .PARAMETER Database
            Path to the Keepass database (.kdbx file)
        .PARAMETER ProfileName
            Name of the profile entry
        .PARAMETER MasterKey
            Path to the keyfile (.key file) used to open the database
        .PARAMETER Keyfile
            Path to the keyfile (.key file) used to open the database
        .PARAMETER UseWindowsAccount
            Use the current windows account as an authentication method
    #>
    [CmdletBinding(DefaultParameterSetName = 'Profile')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $Database,

        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'CompositeKey')]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'Profile')]
        [AllowNull()]
        [PSObject] $MasterKey,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $KeyPath,

        [Parameter(Position = 3, ParameterSetName = 'CompositeKey')]
        [Switch] $UseWindowsAccount
    )
    process
    {
        ## Create KP Database Object
        try
        {
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }
        catch
        {
            Import-KPLibrary
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }

        ## Create KP CompositeKey Object
        $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

        ## Validate MasterKey Type
        if(($MasterKey -isnot [PSCredential]) -and ($MasterKey -isnot [SecureString]) -and $MasterKey)
        {
            Write-Error -Message ('[PROCESS] The MasterKey of type: ({0}). Is not Supported Please supply a MasterKey of Types (SecureString or PSCredential).' -f $($MasterKey.GetType().Name)) -Category InvalidType -TargetObject $MasterKey -RecommendedAction 'Provide a MasterKey of Type PSCredential or SecureString'
        }

        ## Get Profile Values
        if($PSCmdlet.ParameterSetName -eq 'Profile')
        {
            $KeepassConfigurationObject = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName

            if(-not $KeepassConfigurationObject)
            {
                throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            }

            $Database = $KeepassConfigurationObject.DatabasePath
            if($KeepassConfigurationObject.KeyPath -ne '' ){ $KeyPath = $KeepassConfigurationObject.KeyPath }
            [Switch] $UseWindowsAccount = $KeepassConfigurationObject.UseNetworkAccount
            [Switch] $UseMasterKey = $KeepassConfigurationObject.UseMasterKey

            ## Prompt for MasterKey if specified in the profile and was not provided.
            if($UseMasterKey -and -not $MasterKey)
            {
                $MasterKey = $Host.ui.PromptForCredential('KeePassCredential', 'Please enter your KeePass password.', 'KeePass', 'KeePass')
            }
        }
        ## Added this separation for easier future Management.
        elseif($PSCmdlet.ParameterSetName -eq 'CompositeKey')
        {
            $UseMasterKey = if($MasterKey){ $true }
        }

        ## Handle if the master key is a PSCredential
        if($MasterKey -is [PSCredential])
        {
            [SecureString] $MasterKey = $MasterKey.Password
        }

        ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
        $DatabaseItem = Get-Item -Path $Database -ErrorAction Stop

        ## Start Building CompositeKey
        ## Order in which the CompositeKey is created is important and must follow the order of : MasterKey, KeyFile, Windows Account
        if($UseMasterKey)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterKey)))))
        }

        if($KeyPath)
        {
            try
            {
                ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
                $KeyPathItem = Get-Item $KeyPath -ErrorAction Stop
                $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpKeyfile($KeyPathItem.FullName)))
            }
            catch
            {
                ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
                Write-Warning ('Could not read the specfied Key file [{0}].' -f $KeyPathItem.FullName)
            }
        }

        if($UseWindowsAccount)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
        }

        ## Create IOConnection Object
        $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
        $IOInfo.Path = $DatabaseItem.FullName

        ## We currently are not using a status logger hence the null.
        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

        ## Connect, Open and Return Database Object
        $DatabaseObject.Open($IOInfo, $CompositeKey, $IStatusLogger) | Out-Null
        $DatabaseObject

        ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
        if(-not $DatabaseObject.IsOpen)
        {
            Throw 'InvalidDatabaseConnectionException : The database is not open.'
        }
    }
}

function Remove-KPConnection
{
    <#
        .SYNOPSIS
            This Function Removes a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Removes a Connection to a KeePass Database.
        .EXAMPLE
            PS> Remove-KPConnection -KeePassConnection $DB

            This Example will Remove/Close a KeePass Database Connection using a pre-defined KeePass DB connection.
        .PARAMETER KeePassConnection
            This is the KeePass Connection to be Closed
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection
    )
    process
    {
        try
        {
            ## Close KeePass Database Connection
            if( $KeePassConnection.IsOpen)
            {
                $KeePassConnection.Close()
            }
            else
            {
                Write-Warning -Message '[PROCESS] The KeePass Database Specified is already closed or does not exist.'
                Throw 'The KeePass Database Specified is already closed or does not exist.'
            }

        }
        catch [Exception]
        {
            Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
            Throw $_
        }
    }
}

function Get-KPDynamicParameters
{
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Int] $DBProfilePosition,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Int] $MasterKeyPosition,

        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Int] $PwIconPosition
    )
    process
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList = (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            ### DatabaseProfileName Param
            $DBProfileParameterName = 'DatabaseProfileName'
            $DBProfileAttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $DBProfileParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $DBProfileParameterAttribute.Mandatory = $true
            $DBProfileParameterAttribute.Position = $DBProfilePosition

            $DBProfileAttributeCollection.Add($DBProfileParameterAttribute)

            $DBProfileValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($DatabaseProfileList)
            $DBProfileAttributeCollection.Add($DBProfileValidateSetAttribute)

            ## Create and Define Allias Attribute
            $DBProfileAliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $DBProfileAttributeCollection.Add($DBProfileAliasAttribute)

            ### MasterKey Param
            $MasterKeyParameterName = 'MasterKey'
            $MasterKeyAttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $MasterKeyParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $MasterKeyParameterAttribute.Mandatory = $false
            $MasterKeyParameterAttribute.Position = $MasterKeyPosition
            $MasterKeyAttributeCollection.Add($MasterKeyParameterAttribute)

            $MasterKeyValidateAttribute = New-Object -TypeName System.Management.Automation.ValidateNotNullOrEmptyAttribute
            $MasterKeyAttributeCollection.Add($MasterKeyValidateAttribute)

            ### PwIcon Enum Param
            if($PwIconPosition)
            {
                $PwIconEnum = [KeePassLib.PwIcon].GetEnumValues()
                $IconEnumParameterName = 'IconName'

                $IconEnumAttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
                $IconEnumParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
                $IconEnumParameterAttribute.Mandatory = $false
                $IconEnumParameterAttribute.Position = $PwIconPosition
                $IconEnumAttributeCollection.Add($IconEnumParameterAttribute)

                $IconEnumValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($PwIconEnum)
                $IconEnumAttributeCollection.Add($IconEnumValidateSetAttribute)

                ## Create and Define Allias Attribute
                $IconEnumAliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Icon')
                $IconEnumAttributeCollection.Add($IconEnumAliasAttribute)
                $IconEnumRuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($IconEnumParameterName, [KeePassLib.PwIcon], $IconEnumAttributeCollection)
            }


            ## Create,Define, and Return DynamicParam
            $MasterKeyRuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($MasterKeyParameterName, [SecureString], $MasterKeyAttributeCollection)
            $MasterKeyRuntimeParameter.Value = $null
            $DBProfileRuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($DBProfileParameterName, [String], $DBProfileAttributeCollection)



            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($DBProfileParameterName, $DBProfileRuntimeParameter)
            $RuntimeParameterDictionary.Add($MasterKeyParameterName, $MasterKeyRuntimeParameter)

            if($PwIconPosition)
            {
                $RuntimeParameterDictionary.Add($IconEnumParameterName, $IconEnumRuntimeParameter)
            }

            return $RuntimeParameterDictionary
        }
    }
}

function Get-KPEntry
{
    <#
        .SYNOPSIS
            This function will lookup and Return KeePass one or more KeePass Entries.
        .DESCRIPTION
            This function will lookup Return KeePass Entry(ies). It supports basic lookup filtering.
        .EXAMPLE
            PS> Get-KPEntryBase -KeePassConnection $DB -UserName "MyUser"

            This Example will return all entries that have the UserName "MyUser"
        .EXAMPLE
            PS> Get-KPEntry -KeePassConnection $DB -KeePassGroup $KpGroup

            This Example will return all entries that are in the specified group.
        .EXAMPLE
            PS> Get-KPEntry -KeePassConnection $DB -UserName "AUserName"

            This Example will return all entries have the UserName "AUserName"
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            This is the KeePass Group Object in which to search for entries.
        .PARAMETER Title
            This is a Title of one or more KeePass Entries.
        .PARAMETER UserName
            This is the UserName of one or more KeePass Entries.
        .PARAMETER KeePassUuid
            Specify the KeePass Entry Uuid for reverse lookup.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwEntry')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'UUID', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Uuid')]
        [KeePassLib.PwUuid] $KeePassUuid,

        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'Group')]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'Title')]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3, Mandatory = $false, ParameterSetName = 'Group')]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'Title')]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'UserName')]
        [ValidateNotNullOrEmpty()]
        [String] $UserName
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }
    }
    process
    {
        ## Get Entries and Filter
        $KeePassItems = $KeePassConnection.RootGroup.GetEntries($true)

        if($PSCmdlet.ParameterSetName -eq 'UUID')
        {
            $KeePassItems  | Where-Object { $KeePassUuid.CompareTo($_.Uuid) -eq 0 }
        }
        else
        {
            ## This a lame way of filtering.
            if ($KeePassGroup)
            {
                $KeePassItems = foreach($_keepassItem in $KeePassItems)
                {
                    if($KeePassGroup.Contains($_keepassItem.ParentGroup))
                    {
                        $_keepassItem
                    }
                }
            }
            if ($Title)
            {
                $KeePassItems = foreach($_keepassItem in $KeePassItems)
                {
                    if($_keepassItem.Strings.ReadSafe('Title').ToLower().Equals($Title.ToLower()))
                    {
                        $_keepassItem
                    }
                }
            }
            if ($UserName)
            {
                $KeePassItems = foreach($_keepassItem in $KeePassItems)
                {
                    if($_keepassItem.Strings.ReadSafe('UserName').ToLower().Equals($UserName.ToLower()))
                    {
                        $_keepassItem
                    }
                }
            }

            ## Return results
            $KeePassItems
        }

    }
}

function Add-KPEntry
{
    <#
        .SYNOPSIS
            This Function will add a new entry to a KeePass Database Group.
        .DESCRIPTION
            This Function will add a new entry to a KeePass Database Group.

            Currently This function supportes the basic fields for creating a new KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            This is the KeePass GroupObject to add the new Entry to.
        .PARAMETER Title
            This is the Title of the New KeePass Entry.
        .PARAMETER UserName
            This is the UserName of the New KeePass Entry.
        .PARAMETER KeePassPassword
            This is the Password of the New KeePass Entry.
        .PARAMETER Notes
            This is the Notes of the New KeePass Entry.
        .PARAMETER URL
            This is the URL of the New KeePass Entry.
        .PARAMETER PassThru
            Returns the New KeePass Entry after creation.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2, Mandatory = $false)]
        [String] $Title,

        [Parameter(Position = 3, Mandatory = $false)]
        [String] $UserName,

        [Parameter(Position = 4, Mandatory = $false)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5, Mandatory = $false)]
        [String] $Notes,

        [Parameter(Position = 6, Mandatory = $false)]
        [String] $URL,

        [Parameter(Position = 7, Mandatory = $false)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 8, Mandatory = $false)]
        [Switch] $PassThru
    )
    begin
    {

        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
        }

        try
        {
            $KeePassEntry = New-Object KeePassLib.PwEntry($true, $true) -ErrorAction Stop -ErrorVariable ErrorNewPwEntryObject
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpEntry Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
                Write-Warning -Message ('[BEGIN] {0}' -f $ErrorNewPwEntryObject.ErrorRecord.Message)
                Throw $_
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
    }
    process
    {
        if(-not (Test-KPPasswordValue $KeePassPassword))
        {
            Write-Warning -Message '[PROCESS] Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
            Write-Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
            Throw 'Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
        }

        if($Title)
        {
            $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
            $KeePassEntry.Strings.Set('Title', $SecureTitle)
        }

        if($UserName)
        {
            $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
            $KeePassEntry.Strings.Set('UserName', $SecureUser)
        }

        if($KeePassPassword)
        {
            if($KeePassPassword.GetType().Name -eq 'SecureString')
            {
                $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
            }
            elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
            {
                $KeePassSecurePasswordString = $KeePassPassword
            }
            $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
        }
        else
        {
            ## get password based on default pattern
            $KeePassSecurePasswordString = New-KeePassPassword
            $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
        }

        if($Notes)
        {
            $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
            $KeePassEntry.Strings.Set('Notes', $SecureNotes)
        }

        if($URL)
        {
            $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
            $KeePassEntry.Strings.Set('URL', $SecureURL)
        }

        if($IconName)
        {
            if($IconName -ne $KeePassEntry.IconId)
            {
                $KeePassEntry.IconId = $IconName
            }
        }

        #Add to Group
        $KeePassGroup.AddEntry($KeePassEntry, $true)

        #save database
        $KeePassConnection.Save($null)

        if($PassThru)
        {
            $KeePassEntry
        }
    }
}

function Set-KPEntry
{
    <#
        .SYNOPSIS
            This Function will update a entry.
        .DESCRIPTION
            This Function will update a entry.

            Currently This function supportes the basic fields for a KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to update/set atrributes.
        .PARAMETER KeePassGroup
            Specifiy this if you want Move the KeePassEntry to another Group
        .PARAMETER Title
            This is the Title to update/set.
        .PARAMETER UserName
            This is the UserName to update/set.
        .PARAMETER KeePassPassword
            This is the Password to update/set.
        .PARAMETER Notes
            This is the Notes to update/set.
        .PARAMETER URL
            This is the URL to update/set.
        .PARAMETER PassThru
            Returns the updated KeePass Entry after updating.
        .PARAMETER Force
            Specify to force updating the KeePass Entry.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2, Mandatory = $false)]
        [String] $Title,

        [Parameter(Position = 3, Mandatory = $false)]
        [String] $UserName,

        [Parameter(Position = 4, Mandatory = $false)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5, Mandatory = $false)]
        [String] $Notes,

        [Parameter(Position = 6, Mandatory = $false)]
        [String] $URL,

        [Parameter(Position = 7, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 8, Mandatory = $false)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 9, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 10, Mandatory = $false)]
        [Switch] $Force
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }
    }
    process
    {
        if(-not (Test-KPPasswordValue $KeePassPassword))
        {
            Write-Warning -Message '[PROCESS] Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
            Write-Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
            Throw 'Please provide a KeePassPassword Of Type SecureString or KeePassLib.Security.ProtectedString.'
        }

        ## Confirm or Force
        if($Force -or $PSCmdlet.ShouldProcess("Title: $($KeePassEntry.Strings.ReadSafe('Title')). `n`tUserName: $($KeePassEntry.Strings.ReadSafe('UserName')). `n`tGroup Path $($KeePassEntry.ParentGroup.GetFullPath('/', $true))"))
        {
            if($Title)
            {
                $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                $KeePassEntry.Strings.Set('Title', $SecureTitle)
            }

            if($UserName)
            {
                $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                $KeePassEntry.Strings.Set('UserName', $SecureUser)
            }

            if($KeePassPassword)
            {
                if($KeePassPassword.GetType().Name -eq 'SecureString')
                {
                    $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                    $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                }
                elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                {
                    $KeePassSecurePasswordString = $KeePassPassword
                }
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }

            if($Notes)
            {
                $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                $KeePassEntry.Strings.Set('Notes', $SecureNotes)
            }

            if($URL)
            {
                $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                $KeePassEntry.Strings.Set('URL', $SecureURL)
            }

            if($IconName)
            {
                if($IconName -ne $KeePassEntry.IconId)
                {
                    $KeePassEntry.IconId = $IconName
                }
            }

            ## If you are moving the entry to another group then take these actions.
            if($KeePassGroup)
            {
                ## Make Full Copy of Entry
                $NewKeePassEntry = $KeePassEntry.CloneDeep()
                ## Assign New Uuid to CloneDeep
                $NewKeePassEntry.Uuid = New-Object KeePassLib.PwUuid($true)
                ## Add Clone to Specified group
                $KeePassGroup.AddEntry($NewKeePassEntry, $true)
                ## Save for safety
                $KeePassConnection.Save($null)
                ## Delete previous entry
                ## Hide output
                $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry) > $null

                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $NewKeePassEntry
                }
            }

            ## user "colaloc" added this line. comment: we must change LastModificationTime to prevent synchronization problems
            $KeePassEntry.LastModificationTime = Get-Date
            ## user "colaloc" added this line. comment: any changes must be saved!
            $KeePassConnection.Save($null)
        }
    }
}

function Remove-KPEntry
{
    <#
        .SYNOPSIS
            Remove a Specific KeePass Entry.
        .DESCRIPTION
            Remove a Specified KeePass Database Entry.
         .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KPConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to be deleted.
        .PARAMETER NoRecycle
            Specify this flag to Permanently delete an entry. (ei skip the recycle bin)
        .PARAMETER Force
            Specify this flag to forcefully delete an entry.
        .EXAMPLE
            PS> Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KeePassEntryObject

            This Will remove a keepass database entry and prompt for confirmation.
        .INPUTS
            Strings
            KeePassLib.PwDatabase
            KeePassLib.PwEntry
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = "High"
    )]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [Switch] $NoRecycle,

        [Parameter(
            Mandatory = $false,
            Position = 3
        )]
        [Switch] $Force
    )
    begin
    {

        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
        }

        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }
        $EntryDisplayName = "$($KeePassEntry.ParentGroup.GetFullPath('/', $true))/$($KeePassEntry.Strings.ReadSafe('Title'))"
    }
    process
    {
        if($Force -or $PSCmdlet.ShouldProcess($($EntryDisplayName)))
        {
            if($RecycleBin -and -not $NoRecycle)
            {
                ## Make Copy of the group to be recycled.
                $DeletedKeePassEntry = $KeePassEntry.CloneDeep()
                ## Generate a new Uuid and update the copy fo the group
                $DeletedKeePassEntry.Uuid = (New-Object KeePassLib.PwUuid($true))
                ## Add the copy to the recycle bin, with take ownership set to true
                $RecycleBin.AddEntry($DeletedKeePassEntry, $true)
                ## Save for safety
                $KeePassConnection.Save($null)
                ## Delete Original Entry
                $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry) > $null
                ## Save again
                $KeePassConnection.Save($null)
                Write-Verbose -Message "[PROCESS] Group has been Recycled."
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue("Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.", "Do you want to continue to Permanently Delete this Entry: ($($EntryDisplayName))?"))
                {
                    ## Deletes the specified group
                    $IsRemoved = $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry)

                    if(-not $IsRemoved)
                    {
                        Write-Warning -Message "[PROCESS] Unknown Error has occured. Failed to Remove Entry ($($EntryDisplayName))"
                        Throw "Failed to Remove Entry $($EntryDisplayName)"
                    }
                    else
                    {
                        Write-Verbose -Message "[PROCESS] Entry ($($EntryDisplayName)) has been Removed."
                        $KeePassConnection.Save($null)
                    }
                }
            }
        }
    }
}

function Get-KPGroup
{
    <#
        .SYNOPSIS
            Gets a KeePass Group Object.
        .DESCRIPTION
            Gets a KeePass Group Object. Type: KeePassLib.PwGroup
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -FullPath 'full/KPDatabase/pathtoGroup'

            This Example will return a KeePassLib.PwGroup array Object with the full group path specified.
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -GroupName 'Test Group'

            This Example will return a KeePassLib.PwGroup array Object with the groups that have the specified name.
        .PARAMETER KeePassConnection
            Specify the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER FullPath
            Specify the FullPath of a Group or Groups in a KPDB
        .PARAMETER GroupName
            Specify the GroupName of a Group or Groups in a KPDB.
        .PARAMETER KeePassUuid
            Specify the Uuid of the Group.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwGroup')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Full')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Partial')]
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'None')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Full')]
        [ValidateNotNullOrEmpty()]
        [String] $FullPath,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Partial')]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }

        try
        {
            [KeePassLib.PwGroup[]] $KeePassOutGroups = $null
            [KeePassLib.PwGroup[]] $KeePassGroups = $KeePassConnection.RootGroup
            $KeePassGroups += $KeePassConnection.RootGroup.GetFlatGroupList()
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Get-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message ('[BEGIN] {0}' -f $ErrorNewPwGroupObject.ErrorRecord.Message)
                Throw $_
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
    }
    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Full')
        {
            foreach($_keepassGroup in $KeePassGroups)
            {
                if($_keepassGroup.GetFullPath('/', $true).ToLower().Equals($FullPath.ToLower()))
                {
                    $_keepassGroup
                }
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Partial')
        {
            foreach($_keepassGroup in $KeePassGroups)
            {
                if($_keepassGroup.Name.ToLower().Equals($GroupName.ToLower()))
                {
                    $_keepassGroup
                }
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'None')
        {
            $KeePassGroups
        }
    }
}

function Add-KPGroup
{
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER PassThru
            Specify to return the new keepass group object.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 3, Mandatory = $false)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 4, Mandatory = $false)]
        [Switch] $PassThru
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }

        try
        {
            [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message ('[BEGIN] {0}' -f $ErrorNewPwGroupObject.ErrorRecord.Message)
                Throw $_
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
    }
    process
    {
        $KeePassGroup.Name = $GroupName
        if($IconName -ne $KeePassGroup.IconId)
        {
            $KeePassGroup.IconId = $IconName
        }
        $KeePassParentGroup.AddGroup($KeePassGroup, $true)
        $KeePassConnection.Save($null)

        if($PassThru)
        {
            $KeePassGroup
        }
    }
}

function Set-KPGroup
{
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER PassThru
            Specify to return the updated group object.
        .PARAMETER Force
            Specify to force updating the group.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2, Mandatory = $false)]
        [String] $GroupName,

        [Parameter(Position = 3, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 4, Mandatory = $false)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 5, Mandatory = $false)]
        [Switch] $PassThru,

        [Parameter(Position = 6, Mandatory = $false)]
        [Switch] $Force
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }
    }
    process
    {
        if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
        {
            if($GroupName)
            {
                $KeePassGroup.Name = $GroupName
            }

            if($IconName -ne $KeePassGroup.IconId)
            {
                $KeePassGroup.IconId = $IconName
            }

            if($KeePassParentGroup)
            {
                if($KeePassGroup.ParentGroup.Uuid.CompareTo($KeePassParentGroup.Uuid) -ne 0 )
                {
                    $UpdatedKeePassGroup = $KeePassGroup.CloneDeep()
                    $UpdatedKeePassGroup.Uuid = New-Object KeePassLib.PwUuid($true)
                    $KeePassParentGroup.AddGroup($UpdatedKeePassGroup, $true, $true)
                    $KeePassConnection.Save($null)
                    $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                    $KeePassConnection.Save($null)
                    $KeePassGroup = $UpdatedKeePassGroup
                }
            }
            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassGroup
            }
        }
    }
}

function Remove-KPGroup
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Group
        .DESCRIPTION
            Function to remove a specified KeePass Group.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            Specify the Group to be removed.
        .PARAMETER NoRecycle
            Specify if you do not want the group to go to the Recycle Bin.
        .PARAMETER Force
            Specify to forcefully remove a group.
        .EXAMPLE
            PS> Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject

            Removes the specified account. Prompts before deletion and will put to recyclebin if there is one.
        .INPUTS
            KeePassLib.PwDatabase
            KeePassLib.PwGroup
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2, Mandatory = $false)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3, Mandatory = $false)]
        [Switch] $Force
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            Throw 'The KeePass Connection Sepcified is not open or does not exist.'
        }

        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }
    }
    process
    {
        if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
        {
            if($RecycleBin -and -not $NoRecycle)
            {
                ## Make Copy of the group to be recycled.
                $DeletedKeePassGroup = $KeePassGroup.CloneDeep()
                ## Generate a new Uuid and update the copy fo the group
                $DeletedKeePassGroup.Uuid = (New-Object KeePassLib.PwUuid($true))
                ## Add the copy to the recycle bin, with take ownership set to true
                $RecycleBin.AddGroup($DeletedKeePassGroup, $true, $true)
                $KeePassConnection.Save($null)
                $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                $KeePassConnection.Save($null)
                Write-Verbose -Message '[PROCESS] Group has been Recycled.'
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Do you want to continue to Permanently Delete this Group: ($($KeePassGroup.GetFullPath('/', $true)))?"))
                {
                    ## Deletes the specified group
                    $IsRemoved = $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup)
                    if(-not $IsRemoved)
                    {
                        Write-Warning -Message ('[PROCESS] Unknown Error has occured. Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true))
                        Throw 'Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true)
                    }
                    else
                    {
                        Write-Verbose -Message ('[PROCESS] Group ({0}) has been Removed.' -f $KeePassGroup.GetFullPath('/', $true))
                        $KeePassConnection.Save($null)
                    }
                }
            }
        }
    }
}

function Test-KPPasswordValue
{
    param
    (
        [PSObject] $PassValue
    )
    if(-not $PassValue)
    {
        $true
    }
    elseif($PassValue.GetType().Name -eq 'SecureString')
    {
        $true
    }
    elseif($PassValue.GetType().Name -eq 'ProtectedString')
    {
        $true
    }
    else
    {
        $false
    }
}

function ConvertFrom-KPProtectedString
{
    <#
        .SYNOPSIS
            This Function will Convert a KeePass ProtectedString to Plain Text.
        .DESCRIPTION
            This Function will Convert a KeePassLib.Security.ProtectedString to Plain Text.

            This Would Primarily be used for Reading Title,UserName,Password,Notes, and URL ProtectedString Values.
        .EXAMPLE
            PS>Get-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 21 | ConvertFrom-KeePassProtectedString

            This Example will created a password using the specified options and convert the resulting password to a string.
        .PARAMETER KeePassProtectedString
            This is the KeePassLib.Security.ProtectedString to be converted to plain text
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [KeePassLib.Security.ProtectedString] $KeePassProtectedString
    )
    process
    {
        $KeePassProtectedString.ReadSafe()
    }
}

function ConvertTo-KPPSObject
{
    <#
        .SYNOPSIS
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.
        .DESCRIPTION
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.

            It will get the Protected Strings from the database like, Title,UserName,Password,URL,Notes.

            It currently returns Most frequently used data about an entry and excludes extensive metadata such as-
            Foreground Color, Icon, ect.
        .EXAMPLE
            PS> ConvertTo-KPPsObject -KeePassEntry $Entry

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .EXAMPLE
            PS> Get-KeePassEntry -KeePassonnection $DB -UserName "AUserName" | ConvertTo-KeePassPsObject

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .PARAMETER KeePassEntry
            This is the one or more KeePass Entries to be converted.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Entry')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Entry')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $KeePassEntry,
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup
    )
    process
    {
        if($PSCmdlet.ParameterSetName -eq 'Entry')
        {
            foreach ($_keepassItem in $KeePassEntry)
            {
                ## Build Object
                $KeePassPsObject = New-Object -TypeName PSObject
                $KeePassPsObject | Add-Member -Name 'Uuid' -MemberType NoteProperty -Value $_keepassItem.Uuid
                $KeePassPsObject | Add-Member -Name 'CreationTime' -MemberType NoteProperty -Value $_keepassItem.CreationTime
                $KeePassPsObject | Add-Member -Name 'Expires' -MemberType NoteProperty -Value $_keepassItem.Expires
                $KeePassPsObject | Add-Member -Name 'ExpireTime' -MemberType NoteProperty -Value $_keepassItem.ExpiryTime
                $KeePassPsObject | Add-Member -Name 'LastAccessTime' -MemberType NoteProperty -Value $_keepassItem.LastAccessTime
                $KeePassPsObject | Add-Member -Name 'LastModificationTime' -MemberType NoteProperty -Value $_keepassItem.LastModificationTime
                $KeePassPsObject | Add-Member -Name 'LocationChanged' -MemberType NoteProperty -Value $_keepassItem.LocationChanged
                $KeePassPsObject | Add-Member -Name 'Tags' -MemberType NoteProperty -Value $_keepassItem.Tags
                $KeePassPsObject | Add-Member -Name 'Touched' -MemberType NoteProperty -Value $_keepassItem.Touched
                $KeePassPsObject | Add-Member -Name 'UsageCount' -MemberType NoteProperty -Value $_keepassItem.UsageCount
                $KeePassPsObject | Add-Member -Name 'ParentGroup' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.Name
                $KeePassPsObject | Add-Member -Name 'FullPath' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.GetFullPath('/', $true)
                $KeePassPsObject | Add-Member -Name 'Title' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('Title')
                $KeePassPsObject | Add-Member -Name 'UserName' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('UserName')
                $KeePassPsObject | Add-Member -Name 'Password' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('Password')
                $KeePassPsObject | Add-Member -Name 'URL' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('URL')
                $KeePassPsObject | Add-Member -Name 'Notes' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe('Notes')
                $KeePassPsObject | Add-Member -Name 'IconId' -MemberType NoteProperty -Value $_keepassItem.IconId

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Entry')

                ## Return Object
                $KeePassPsObject
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Group')
        {
            foreach ($_keepassItem in $KeePassGroup)
            {
                if($_keepassItem.ParentGroup.Name)
                {
                    $FullPath = $_keepassItem.ParentGroup.GetFullPath('/', $true)
                }
                else
                {
                    $FullPath = ''
                }
                $KeePassPsObject = New-Object -TypeName PSObject
                $KeePassPsObject | Add-Member -Name 'Uuid' -MemberType NoteProperty -Value $_keepassItem.Uuid
                $KeePassPsObject | Add-Member -Name 'Name' -MemberType NoteProperty -Value $_keepassItem.Name
                $KeePassPsObject | Add-Member -Name 'CreationTime' -MemberType NoteProperty -Value $_keepassItem.CreationTime
                $KeePassPsObject | Add-Member -Name 'Expires' -MemberType NoteProperty -Value $_keepassItem.Expires
                $KeePassPsObject | Add-Member -Name 'ExpireTime' -MemberType NoteProperty -Value $_keepassItem.ExpiryTime
                $KeePassPsObject | Add-Member -Name 'LastAccessTime' -MemberType NoteProperty -Value $_keepassItem.LastAccessTime
                $KeePassPsObject | Add-Member -Name 'LastModificationTime' -MemberType NoteProperty -Value $_keepassItem.LastModificationTime
                $KeePassPsObject | Add-Member -Name 'LocationChanged' -MemberType NoteProperty -Value $_keepassItem.LocationChanged
                $KeePassPsObject | Add-Member -Name 'Touched' -MemberType NoteProperty -Value $_keepassItem.Touched
                $KeePassPsObject | Add-Member -Name 'UsageCount' -MemberType NoteProperty -Value $_keepassItem.UsageCount
                $KeePassPsObject | Add-Member -Name 'ParentGroup' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.Name
                $KeePassPsObject | Add-Member -Name 'FullPath' -MemberType NoteProperty -Value $FullPath
                $KeePassPsObject | Add-Member -Name 'Groups' -MemberType NoteProperty -Value $_keepassItem.Groups
                $KeePassPsObject | Add-Member -Name 'EntryCount' -MemberType NoteProperty -Value $_keepassItem.Entries.Count
                $KeePassPsObject | Add-Member -Name 'IconId' -MemberType NoteProperty -Value $_keepassItem.IconId

                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Group')
                $PSKeePassGroupDisplaySet = 'Name', 'EntryCount', 'FullPath', 'IconId'
                $PSKeePassGroupDefaultPropertySet = New-Object -TypeName System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [String[]] $PSKeePassGroupDisplaySet)
                $PSKeePassGroupStandardMembers = [System.Management.Automation.PSMemberInfo[]] @($PSKeePassGroupDefaultPropertySet)

                $KeePassPsObject | Add-Member MemberSet PSStandardMembers $PSKeePassGroupStandardMembers

                $KeePassPsObject
            }
        }
    }
}

function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        Write-Debug -Message '[PROCESS] Checking if KeePassLib is already loaded.'
        $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()
        $KeePassAssembly = $LoadedAssemblies | Where-Object { $_.FullName -match "KeePassLib"}

        if($KeePassAssembly)
        {
            $KeePassAssemblyInfo = @{
                'Name'     = $KeePassAssembly.FullName.Replace(' ', '').Split(',')[0]
                'Version'  = $KeePassAssembly.FullName.Replace(' ', '').Split(',')[1].Split('=')[1]
                'Location' = $KeePassAssembly.Location
            }

            if($KeePassAssemblyInfo.Name -eq 'KeePassLib')
            {
                if($KeePassAssemblyInfo.Version -eq '2.30.0.15901')
                {
                    Write-Verbose -Message ('KeePassLib has already been loaded, from: {0}.' -f $KeePassAssemblyInfo.Location)
                    Write-Debug -Message ('KeePassLib Assembly Name: {0}, Version: {1}' -f $KeePassAssemblyInfo.Name, $KeePassAssemblyInfo.Version)
                    $KeePassAssemblyIsLoaded = $true
                }
                else
                {
                    Write-Debug -Message '[PROCESS] A KeePassLib Assembly is loaded but it does not match the required version: ''2.30.0.15901'''
                    Write-Debug -Message ('[PROCESS] Version Found: {0}' -f $KeePassAssemblyInfo.Version)
                    Write-Debug -Message '[PROCESS] Will continue to load the correct version.'
                }
            }
            else
            {
                Write-Debug -Message '[PROCESS] No Loaded Assembly found for KeePassLib. Will Continue to load the Assembly.'
            }
        }

        if(-not $KeePassAssemblyIsLoaded)
        {
            $Path = Resolve-Path ('{0}\bin\KeePassLib.dll' -f $PSScriptRoot)
            Add-Type -Path $Path.Path
        }
    }
}

## Source KpLib
Import-KPLibrary

if (-not(Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
{
    Write-Warning -Message '**IMPORTANT NOTE:** Please always keep an up-to-date backup of your keepass database files and key files if used.'
    Write-Warning -Message 'This message will not show again on next import.'
    if(-not $(Restore-KPConfigurationFile))
    {
        New-KPConfigurationFile
    }
}
