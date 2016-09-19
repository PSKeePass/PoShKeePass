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
                * Path Separator is the foward slash character '/'
                * The top level directory aka the database name should not be included in the path.
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
            *This is a Dynamic Parameter that is populated from the KeePassConfiguration.xml. 
                *You can generated this file by running the New-KeePassDatabaseConfiguration function.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -AsPlainText

            This Example will return all enties in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General' -AsPlainText

            This Example will return all entries in plain text format from the General folder of the keepass database with the profile name TEST.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    param
    (
        [Parameter(Position = 0 ,Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassEntryGroupPath,
        [Parameter(Position = 1 ,Mandatory = $false)]
        [Switch] $AsPlainText
    )
    dynamicparam
    {
        ## Get a list of all database profiles saved to the config xml.
        $DatabaseProfileList =  (Get-KeePassDatabaseConfiguration).Name
        ## If no profiles exists do not return the parameter.
        if($DatabaseProfileList)
        {
            $ParameterName = 'DatabaseProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 4
            # $ParameterAttribute.ValueFromPipelineByPropertyName = $true
            # $ParameterAttribute.ParameterSetName = 'Profile'
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($DatabaseProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ## Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ## Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
            return $RuntimeParameterDictionary
        }
    }
    begin
    {
        ## If there are no database profiles in the the config or the config does not exist error out and prompt use to create a config.
        if($DatabaseProfileList)
        {
            $DatabaseProfileName = $PSBoundParameters[$ParameterName]
        }
        else
        {
            Write-Warning -Message "[BEGIN] There are Currently No Database Configuration Profiles."
            Write-Warning -Message "[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function."
            break
        }

        ## Get the database profile definition
        $DatabaseProfileObject = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
    
        ## prompt user for master key password as SecureString if the profile specifies it uses a master key
        if($DatabaseProfileObject.UseMasterKey -eq 'True')
        {
            $MasterKeySecureString = Read-Host -Prompt "Database MasterKey" -AsSecureString
        }

        ## Convert xml string to boolean
        if($DatabaseProfileObject.UseNetworkAccount -eq 'True'){$UseNetworkAccount = $true}else {$UseNetworkAccount=$false}

        ## Get the KeePass credential object based on the authentication type in the profile definition.
        $KeePassCredentialObject = switch ($DatabaseProfileObject.AuthenticationType) {
            'KeyAndMaster'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -KeyFile $DatabaseProfileObject.KeyPath -MasterKey $MasterKeySecureString
            }
            'Key'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -KeyFile $DatabaseProfileObject.KeyPath -UseNetworkAccount:$UseNetworkAccount
            }
            'Master'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -MasterKey $MasterKeySecureString -UseNetworkAccount:$UseNetworkAccount
            }
        }

        ## Open the database
        $KeePassConnectionObject = Get-KPConnection -KeePassCredential $KeePassCredentialObject
        ## remove any sensitive data
        if($MasterKeySecureString){Remove-Variable -Name MasterKeySecureString}
        if($KeePassCredentialObject){Remove-Variable -Name KeePassCredentialObject}
    }
    process
    {
        if($KeePassEntryGroupPath)
        {   
            ## Get All entries in the specified group
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath
            $ResultEntries = Get-KpEntry -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroup
        }
        else
        {
            ## Get all entries in all groups.
            $ResultEntries = Get-KpEntry -KeePassConnection $KeePassConnectionObject
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

##DEV
## Documentation Needed
function New-KeePassEntry
{
    param
    (
        [Parameter(Position = 0 ,Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position=1,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $Title,

        [Parameter(Position=3,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(Position=4,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.Security.ProtectedString] $KeePassPassword,

        [Parameter(Position=5,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $Notes,

        [Parameter(Position=6,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $URL
    )
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $DatabaseProfileList =  (Get-KeePassDatabaseConfiguration).Name
        if($DatabaseProfileList)
        {
            $ParameterName = 'DatabaseProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            ###ParameterSet Host
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 4
            # $ParameterAttribute.ValueFromPipelineByPropertyName = $true
            # $ParameterAttribute.ParameterSetName = 'Profile'
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($DatabaseProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ##Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ##Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
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
            Write-Warning -Message "[BEGIN] There are Currently No Database Configuration Profiles."
            Write-Warning -Message "[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function."
            break
        }

        $DatabaseProfileObject = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
    
        if($DatabaseProfileObject.UseMasterKey -eq 'True')
        {
            $MasterKeySecureString = Read-Host -Prompt "Database MasterKey" -AsSecureString
        }

        if($DatabaseProfileObject.UseNetworkAccount -eq 'True'){$UseNetworkAccount = $true}else {$UseNetworkAccount=$false}

        $KeePassCredentialObject = switch ($DatabaseProfileObject.AuthenticationType) {
            'KeyAndMaster'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -KeyFile $DatabaseProfileObject.KeyPath -MasterKey $MasterKeySecureString
            }
            'Key'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -KeyFile $DatabaseProfileObject.KeyPath -UseNetworkAccount:$UseNetworkAccount
            }
            'Master'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -MasterKey $MasterKeySecureString -UseNetworkAccount:$UseNetworkAccount
            }
        }

        $KeePassConnectionObject = Get-KPConnection -KeePassCredential $KeePassCredentialObject
        if($MasterKeySecureString){Remove-Variable -Name MasterKeySecureString}
        if($KeePassCredentialObject){Remove-Variable -Name KeePassCredentialObject}
    }
    process
    {
        $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath
        Add-KpEntry -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroup -Title $Title -UserName $UserName -KeePassPassword $KeePassPassword -Notes $Notes -URL $URL
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}


##DEV
## Documentation Needed
function Set-KeePassEntry
{
    param
    (
        [Parameter(Position=0,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position=1,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position=2,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $Title,

        [Parameter(Position=3,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(Position=4,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.Security.ProtectedString] $KeePassPassword,

        [Parameter(Position=5,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $Notes,

        [Parameter(Position=6,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $URL
    )
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $DatabaseProfileList =  (Get-KeePassDatabaseConfiguration).Name
        if($DatabaseProfileList)
        {
            $ParameterName = 'DatabaseProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            ###ParameterSet Host
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 4
            # $ParameterAttribute.ValueFromPipelineByPropertyName = $true
            # $ParameterAttribute.ParameterSetName = 'Profile'
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($DatabaseProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ##Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ##Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
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
            Write-Warning -Message "[BEGIN] There are Currently No Database Configuration Profiles."
            Write-Warning -Message "[BEGIN] Please run the New-KeePassDatabaseConfiguration function before you use this function."
            break
        }

        $DatabaseProfileObject = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
    
        if($DatabaseProfileObject.UseMasterKey -eq 'True')
        {
            $MasterKeySecureString = Read-Host -Prompt "Database MasterKey" -AsSecureString
        }

        if($DatabaseProfileObject.UseNetworkAccount -eq 'True'){$UseNetworkAccount = $true}else {$UseNetworkAccount=$false}

        $KeePassCredentialObject = switch ($DatabaseProfileObject.AuthenticationType) {
            'KeyAndMaster'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -KeyFile $DatabaseProfileObject.KeyPath -MasterKey $MasterKeySecureString
            }
            'Key'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -KeyFile $DatabaseProfileObject.KeyPath -UseNetworkAccount:$UseNetworkAccount
            }
            'Master'
            {
                Get-KPCredential -DatabaseFile $DatabaseProfileObject.DatabasePath -MasterKey $MasterKeySecureString -UseNetworkAccount:$UseNetworkAccount
            }
        }

        $KeePassConnectionObject = Get-KPConnection -KeePassCredential $KeePassCredentialObject
        if($MasterKeySecureString){Remove-Variable -Name MasterKeySecureString}
        if($KeePassCredentialObject){Remove-Variable -Name KeePassCredentialObject}
    }
    process
    {
        $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath
        Set-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KeePassEntry -Title $Title -UserName $UserName -KeePassPassword $KeePassPassword -Notes $Notes -URL $URL -KeePassGroup $KeePassGroup
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}

##DEV
## Need to check if profile by name exists and prompt for what to do
## Need to add option to generate via profile
## Needs Documentation
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
            PS> Get-KpPass

            This Example will generate a Password using the Default KeePass Password Profile.
            Which I believe is -UpperCase -LowerCase -Digites -Length 20
        .EXAMPLE
            PS> Get-KpPass -UpperCase -LowerCase -Digits -Length 20

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9
        .EXAMPLE
            PS> Get-KpPass -UpperCase -LowerCase -Digits -SpecialCharacters -ExcludeCharacters '"' -Length 20

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
    #>
    [CmdletBinding(DefaultParameterSetName='NoProfile')]
    [OutputType('KeePassLib.Security.ProtectedString')]
    param
    (
        [Parameter(Position=0, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $UpperCase,
        [Parameter(Position=1, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $LowerCase,
        [Parameter(Position=2, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $Digits,
        [Parameter(Position=3, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $SpecialCharacters,
        [Parameter(Position=4, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $Minus,
        [Parameter(Position=5, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $UnderScore,
        [Parameter(Position=6, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $Space,
        [Parameter(Position=7, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $Brackets,
        [Parameter(Position=8, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $ExcludeLookALike,
        [Parameter(Position=9, ParameterSetName='NoProfile')]
        [ValidateNotNull()]
        [Switch] $NoRepeatingCharacters,
        [Parameter(Position=10, ParameterSetName='NoProfile')]
        [ValidateNotNullOrEmpty()]
        [string] $ExcludeCharacters,
        [Parameter(Position=11, ParameterSetName='NoProfile')]
        [ValidateNotNullOrEmpty()]
        [int] $Length,
        [Parameter(Position=12, ParameterSetName='NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $SaveAs
    )
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $PasswordProfileList =  (Get-KPPasswordProfile).Name
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
            $RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
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
            $NewProfileObject = '' | Select-Object ProfileName,CharacterSet,ExcludeLookAlike,NoRepeatingCharacters,ExcludeCharacters,Length
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
                
                if($SaveAs)
                {
                    $NewProfileObject.ProfileName = $SaveAs
                    New-KPPasswordProfile -KeePassPasswordObject $NewProfileObject
                }
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Profile')
        {
            $PasswordProfileObject=Get-KPPasswordProfile -PasswordProfileName $PasswordProfileName
            $PassProfile.CharSet.Add($PasswordProfileObject.CharacterSet)
            $PassProfile.ExcludeLookAlike = $PasswordProfileObject.ExlcudeLookAlike
            $PassProfile.NoRepeatingCharacters = $PasswordProfileObject.NoRepeatingCharacters
            $PassProfile.ExcludeCharacters = $PasswordProfileObject.ExcludeCharacters
            $PassProfile.Length = $PasswordProfileObject.Length
        }
       
        ## Create Pass Generator Profile Pool.
        $GenPassPool = New-Object KeePassLib.Cryptography.PasswordGenerator.CustomPwGeneratorPool
        ## Create Out Parameter aka [rel] param.
        [KeePassLib.Security.ProtectedString]$PSOut = New-Object KeePassLib.Security.ProtectedString
        ## Generate Password.
        [KeePassLib.Cryptography.PasswordGenerator.PwGenerator]::Generate([ref] $PSOut, $PassProfile, $null, $GenPassPool) > $null
        # $PSOut.GetType();
        $PSOut
    }
}

##DEV
## Needs Documentation
function New-KeePassDatabaseConfiguration
{
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [String] $DatabasePath,

        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [String] $KeyPath,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ParameterSetName='Master')]
        [Switch] $UseNetworkAccount,

        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Master')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [Switch] $UseMasterKey
    )
    process
    {
        if (-not (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
        {
            Write-Verbose -Message "[PROCESS] A KeePass Configuration File does not exist. One will be generated now."
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if($CheckIfProfileExists)
        {
            Write-Warning -Message "[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: $DatabaseProfileName."
        }
        else
        {
            try
            {
                [xml] $XML = Get-Content("$PSScriptRoot\KeePassConfiguration.xml")
                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $DatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null
                
                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element','DatabasePath','')
                $DatabasePathNode.InnerText = $DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null
                
                $KeyPathNode = $XML.CreateNode('element','KeyPath','')
                $KeyPathNode.InnerText = $KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null
                
                $UseNetworkAccountNode = $XML.CreateNode('element','UseNetworkAccount','')
                $UseNetworkAccountNode.InnerText = $UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null
                
                $UseMasterKeyNode = $XML.CreateNode('element','UseMasterKey','')
                $UseMasterKeyNode.InnerText = $UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null
                
                $AuthenticationTypeNode = $XML.CreateNode('element','AuthenticationType','')
                $AuthenticationTypeNode.InnerText = $PSCmdlet.ParameterSetName
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').AppendChild($DatabaseProfile) | Out-Null
                
                $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")
            }
            catch [Exception]
            {
                Write-Warning -Message "[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ($DatabaseProfileName) to the configuration file."
                Write-Warning -Message "[PROCESS] $($_.Exception.Message)"
                Throw $_ 
            }
        }
    }
}

##DEV
## Needs Documentation
function Remove-KeePassDatabaseConfiguration 
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact='High')]
    param()
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $DatabaseProfileList =  (Get-KeePassDatabaseConfiguration).Name
        if($DatabaseProfileList)
        {
            $ParameterName = 'DatabaseProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            ###ParameterSet Host
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 0
            $ParameterAttribute.ValueFromPipelineByPropertyName = $true
            # $ParameterAttribute.ParameterSetName = 'Profile'
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($DatabaseProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ##Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ##Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
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
            Write-Warning -Message "[BEGIN] There are Currently No Database Configuration Profiles." 
            break
        }
    }
    process
    {
        if (-not (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
        {
            Write-Verbose -Message "[PROCESS] A KeePass Configuration File does not exist."
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
                        [xml]$XML = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
                        $XML.Settings.DatabaseProfiles.Profile  | Where-Object { $_.Name -eq $DatabaseProfileName } | ForEach-Object { $xml.Settings.DatabaseProfiles.RemoveChild($_) } | Out-Null
                        $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")
                    }
                    catch [exception]
                    {
                        Write-Warning -Message "[PROCESS] An exception occured while attempting to remove a KeePass Database Configuration Profile ($DatabaseProfileName)."
                        Write-Warning -Message "[PROCESS] $($_.Exception.Message)"
                        Throw $_
                    }
                }
            }
            else
            {
                Write-Warning -Message "[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: $DatabaseProfileName."
            }
        }
        
    }
}

##DEV
## Needs Documentation
function Get-KeePassDatabaseConfiguration
{
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName
    )
    process
    {
        if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
        {
            [xml]$XML = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
            if($DatabaseProfileName)
            {
                $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -ilike $DatabaseProfileName }
            }
            else
            {
                $XML.Settings.DatabaseProfiles.Profile
            }
        }
        else
        {
            Write-Warning 'No KeePass Configuration has been created.'
        }
    }
}

<#
# Internals
# *These functions below support all of the functions above.
# *Their intended purpose is to be used for advanced scripting.
#>

##DEV
## Needs Documentation
function New-KPConfigurationFile
{
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory = $false
        )]
        [Switch] $Force
    )
    process
    {
        if ((Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml) -and -not $Force)
        {
            Write-Warning -Message "[PROCESS] A KeePass Configuration File already exists. Please rerun with -force to overwrite the existing configuration."
        }
        else
        {
            try
            {
                $Path = "$PSScriptRoot\KeePassConfiguration.xml"

                $XML = New-Object System.Xml.XmlTextWriter($Path,$null)
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
                Write-Warning -Message "[PROCESS] An exception occured while trying to create a new keepass configuration file."
                Write-Warning -Message "[PROCESS] $($_.Exception.Message)"
                Throw $_
            }
            
        }
    }
}

##DEV
## Needs Documentation
function New-KPPasswordProfile
{
    <#
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory = $true
        )]
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
                Write-Warning -Message "[PROCESS] A Password Profile with the specified name ($($KeePassPasswordObject.ProfileName)) already exists."
                break
            }

            [xml] $XML = Get-Content("$PSScriptRoot\KeePassConfiguration.xml")
            ## Create New Profile Element with Name of the new profile
            $PasswordProfile = $XML.CreateElement('Profile')
            $PasswordProfileAtribute = $XML.CreateAttribute('Name')
            $PasswordProfileAtribute.Value = $KeePassPasswordObject.ProfileName
            $PasswordProfile.Attributes.Append($PasswordProfileAtribute) | Out-Null
            
            ## Build and Add Element Nodes
            $CharacterSetNode = $XML.CreateNode('element','CharacterSet','')
            $CharacterSetNode.InnerText = $KeePassPasswordObject.CharacterSet
            $PasswordProfile.AppendChild($CharacterSetNode) | Out-Null
            
            $ExcludeLookAlikeNode = $XML.CreateNode('element','ExcludeLookAlike','')
            $ExcludeLookAlikeNode.InnerText = $KeePassPasswordObject.ExcludeLookAlike
            $PasswordProfile.AppendChild($ExcludeLookAlikeNode) | Out-Null
            
            $NoRepeatingCharactersNode = $XML.CreateNode('element','NoRepeatingCharacters','')
            $NoRepeatingCharactersNode.InnerText = $KeePassPasswordObject.NoRepeatingCharacters
            $PasswordProfile.AppendChild($NoRepeatingCharactersNode) | Out-Null
            
            $ExcludeCharactersNode = $XML.CreateNode('element','ExcludeCharacters','')
            $ExcludeCharactersNode.InnerText = $KeePassPasswordObject.ExcludeCharacters
            $PasswordProfile.AppendChild($ExcludeCharactersNode) | Out-Null
            
            $LengthNode = $XML.CreateNode('element','Length','')
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

##DEV
## Needs Documentation
function Get-KPPasswordProfile
{
    <#
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    process
    {
        if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
        {
            [xml]$XML = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
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

##DEV
## Needs Documentation
function Remove-KPPasswordProfile 
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact='High')]
    param()
    dynamicparam
    {
        ##Create and Define Validate Set Attribute
        $PasswordProfileList =  (Get-KPPasswordProfile).Name
        if($PasswordProfileList)
        {
            $ParameterName = 'PasswordProfileName'
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            ###ParameterSet Host
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $true
            $ParameterAttribute.Position = 0
            $ParameterAttribute.ValueFromPipelineByPropertyName = $true
            # $ParameterAttribute.ParameterSetName = 'Profile'
            $AttributeCollection.Add($ParameterAttribute)

            $ValidateSetAttribute = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($PasswordProfileList)
            $AttributeCollection.Add($ValidateSetAttribute)

            ##Create and Define Allias Attribute
            $AliasAttribute = New-Object -TypeName System.Management.Automation.AliasAttribute('Name')
            $AttributeCollection.Add($AliasAttribute)

            ##Create,Define, and Return DynamicParam
            $RuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
            $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
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
            Write-Warning -Message "[BEGIN] There are Currently No Password Profiles." 
            break
        }
    }
    process
    {
        if (-not (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml))
        {
            Write-Verbose -Message "[PROCESS] A KeePass Configuration File does not exist."
        }
        else
        {
            # $CheckIfProfileExists = Get-KPPasswordProfile -PasswordProfileName $PasswordProfileName

            # if($CheckIfProfileExists)
            # {
                if($PSCmdlet.ShouldProcess($PasswordProfileName))
                {
                    try
                    {
                        [xml]$XML = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
                        $XML.Settings.PasswordProfiles.Profile  | Where-Object { $_.Name -eq $PasswordProfileName } | ForEach-Object { $xml.Settings.PasswordProfiles.RemoveChild($_) } | Out-Null
                        $XML.Save("$PSScriptRoot\KeePassConfiguration.xml")
                    }
                    catch [exception]
                    {
                        Write-Warning -Message "[PROCESS] An exception occured while attempting to remove a KeePass Password Profile ($PasswordProfileName)."
                        Write-Warning -Message "[PROCESS] $($_.Exception.Message)"
                        Throw $_
                    }
                }
            # }
            # else
            # {
            #     Write-Warning -Message "[PROCESS] A KeePass Password Profile does not exists with the specified name: $PasswordProfileName."
            # }
        }
        
    }
}

function Get-KPCredential
{
	<#
        .SYNOPSIS
            This function Creates a Keepass Credential Object to be passed to the keepass module.
        .DESCRIPTION
            This function Creates a Keepass Credential Object to be passed to the keepass module. This will be used to to validate passed
            keepass database credentials and then open said database in a specific way based on passed credentials
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "\\mypath\database.kdbx" -KpKeyPath "\\mypath\database.key"

            This Example will create a keepass credential object to be used when opening a keepass database, using the database file and a keepass kee file.
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "\\mypath\database.kdbx" -KpKeyPath "\\mypath\database.key" -KpMasterKey "MyMasterKeyPassword"

            This Example will create a keepass credential object to be used when opening a keepass database, using the database file, a keepass kee file, and a masterkey password.
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "\\mypath\database.kdbx" -KpMasterKey "MyMasterKeyPassword"

            This Example will create a keepass credential object to be used when opening a keepass database, using the database file and a masterkey password.
        .PARAMETER DatabaseFile
            The path to your Keepass Database File (.kdbx)
        .PARAMETER KeyFile
            The path to your Keepass Encryption Key File (.key)
        .PARAMETER MasterKey
            The Master Key Password to your Keepass Database.
        .INPUTS
            String. All Inputs are passed as a string.
        .OUTPUTS
            System.Management.Automation.PSCustomObject
	#>
    [CmdletBinding(DefaultParameterSetName='Key')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Master')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string] $DatabaseFile,

        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string] $KeyFile,

        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Master')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString] $MasterKey,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ParameterSetName='Master')]
        [switch] $UseNetworkAccount
    )
    process
    {
        try
        {
            $Output = [Ordered] @{
                'DatabaseFile' = $DatabaseFile
                'KeyFile' = $KeyFile
                'MasterKey' = $MasterKey
                'AuthenticationType' = $PSCmdlet.ParameterSetName
                'UseNetworkAccount' = $UseNetworkAccount
            }
        }
        catch [Exception]
        {
            Throw $_.Exception.Message
        }
        finally
        {
            [PSCustomObject] $Output
        }
    }
}

function Get-KPConnection
{
    <#
        .SYNOPSIS
            This Function Creates a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Creates a Connection to a KeePass Database. It Uses a KpCred Object-
            to determine the authentication method. It then connectes to the database and returns-
            an open KeePassLib.PwDatabase object.

            Currently this funciton supports these methods of authentication:
                KeyFile
                Master Password
                Master Password and KeyFile

            Future Versions will support Windows User Authentication Types.
        .EXAMPLE
            PS> Get-KeePassConnection -KeePassCredential $Creds

            This Example will return an KeePass Database Connection using a pre-defined KeePass Credential Object.
        .PARAMETER KeePassCredential
            This is the KeePass Credential Object, that is used to open a connection to the KeePass DB.

            See Get-KeePassCredential in order to generate this credential object.
    #>
    [CmdletBinding()]
    [OutputType('KeePassLib.PwDatabase')]
    param
    (
        [Parameter(Position=0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $KeePassCredential
    )
    process
    {
        ## Create IOConnectionInfo to KPDB using KPLib
        try
        {
            $KeePassIOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
            $KeePassIOConnectionInfo.Path = $KeePassCredential.DatabaseFile
            $KeePassCompositeKey = New-Object KeePassLib.Keys.CompositeKey
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
            Throw $_.Exception
        }

        ## Determine AuthenticationType and Create KPLib CompositeKey
        try
        {
            if ($KeePassCredential.AuthenticationType -eq "Key")
            {
                $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpKeyFile($KeePassCredential.KeyFile)))
                if($KeePassCredential.UseNetworkAccount)
                {
                    $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpUserAccount))
                }
            }
            elseif ($KeePassCredential.AuthenticationType -eq "KeyAndMaster")
            {
                $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassCredential.MasterKey)))))
                # $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpUserAccount))
                $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpKeyFile($KeePassCredential.KeyFile)))
            }
            elseif ($KeePassCredential.AuthenticationType -eq "Master")
            {
                $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassCredential.MasterKey)))))
                if($KeePassCredential.UseNetworkAccount)
                {
                    $KeePassCompositeKey.AddUserKey((New-Object KeePassLib.Keys.KcpUserAccount))
                }
            }
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
            Throw $_.Exception
        }
        finally
        {
            if($KeePassCredential){Remove-Variable -Name KeePassCredential}
        }

        ## Open KPDB Connection
        try
        {
            $KeePassDatabase = New-Object KeePassLib.PwDatabase
            $KeePassDatabase.Open($KeePassIOConnectionInfo, $KeePassCompositeKey, $null)
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
            Throw $_.Exception
        }
        finally
        {
            if($KeePassCompositeKey){Remove-Variable -Name KeePassCompositeKey}
        }
        
        ## Return Open KeePass Database
        $KeePassDatabase
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
        [Parameter(Position=0, Mandatory)]
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
                Write-Warning -Message "[PROCESS] The KeePass Database Specified is already closed or does not exist."    
            }
            
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
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
    #>
    [CmdletBinding(DefaultParameterSetName="")]
    [OutputType('KeePassLib.PwEntry')]
    param
    (
        [Parameter(Position=0,Mandatory,ParameterSetName="Group")]
        [Parameter(Position=0,Mandatory,ParameterSetName="Title")]
        [Parameter(Position=0,Mandatory,ParameterSetName="UserName")]
        [Parameter(Position=0,Mandatory,ParameterSetName="Password")]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position=1,Mandatory,ParameterSetName="Group")]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position=2,Mandatory=$false,ParameterSetName="Group")]
        [Parameter(Position=1,Mandatory,ParameterSetName="Title")]
        [ValidateNotNullOrEmpty()]
        [string] $Title,

        [Parameter(Position=3,Mandatory=$false,ParameterSetName="Group")]
        [Parameter(Position=2,Mandatory=$false,ParameterSetName="Title")]
        [Parameter(Position=1,Mandatory,ParameterSetName="UserName")]
        [ValidateNotNullOrEmpty()]
        [string] $UserName
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
        }
    }
    process
    {
        ## Get Entries and Filter
        $KeePassItems = $KeePassConnection.RootGroup.GetEntries($true)

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
                if($_keepassItem.Strings.ReadSafe("Title").ToLower().Equals($Title.ToLower()))
                {
                    $_keepassItem
                }
            }
        }
        if ($UserName)
        {
             $KeePassItems = foreach($_keepassItem in $KeePassItems)
             {
                 if($_keepassItem.Strings.ReadSafe("UserName").ToLower().Equals($UserName.ToLower()))
                 {
                    $_keepassItem
                 }
             }
        }

        ## Return results
        $KeePassItems
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
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position=0,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position=1,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position=2,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $Title,

        [Parameter(Position=3,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(Position=4,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [KeePassLib.Security.ProtectedString] $KeePassPassword,

        [Parameter(Position=5,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $Notes,

        [Parameter(Position=6,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $URL
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
                Write-Warning -Message "[BEGIN] $($ErrorNewPwEntryObject.ErrorRecord.Message)"
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
        if($Title)
        {
            $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
            $KeePassEntry.Strings.Set("Title", $SecureTitle)
        }

        if($UserName)
        {
            $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
            $KeePassEntry.Strings.Set("UserName", $SecureUser)
        }

        if($KeePassPassword)
        {
            $KeePassEntry.Strings.Set("Password", $KeePassPassword)
        }
        else
        {
            #get password based on default pattern
            $KeePassPassword = New-KeePassPassword
            $KeePassEntry.Strings.Set("Password", $KeePassPassword)
        }

        if($Notes)
        {
            $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
            $KeePassEntry.Strings.Set("Notes", $SecureNotes)
        }

        if($URL)
        {
            $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
            $KeePassEntry.Strings.Set("URL", $SecureURL)
        }

        #Add to Group
        $KeePassGroup.AddEntry($KeePassEntry,$true)

        #save database
        $KeePassConnection.Save($null)
    }
}

## Set/Update a KeePass Group
## Needs Parameter Sets 
## needs parameter atrributes updates
## needs help text update
## Add funcitonality from Set-KeePassEntry above (append notes) or only have that in wrapper funcion
function Set-KPEntry
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
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to update/set atrributes.
        .PARAMETER KeePassGroup
            Specifiy this if you want Move the KeePassEntry to another Group
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
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position=0,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position=1,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position=2,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $Title,

        [Parameter(Position=3,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(Position=4,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [KeePassLib.Security.ProtectedString] $KeePassPassword,

        [Parameter(Position=5,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $Notes,

        [Parameter(Position=6,Mandatory=$false)]
        # [ValidateNotNullOrEmpty()]
        [string] $URL,
        
        [Parameter(Position=7,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
        }
        # try
        # {
        #     $KeePassEntry = New-Object KeePassLib.PwEntry($true, $true) -ErrorAction Stop -ErrorVariable ErrorNewPwEntryObject
        # }
        # catch
        # {
        #     Write-Warning -Message '[BEGIN] An error occured in the Add-KpEntry Cmdlet.'
        #     if($ErrorNewPwGroupObject)
        #     {
        #         Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
        #         Write-Warning -Message "[BEGIN] $($ErrorNewPwEntryObject.ErrorRecord.Message)"
        #         Throw $_
        #     }
        #     else
        #     {
        #         Write-Warning -Message '[BEGIN] An unhandled exception occured.'
        #         Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
        #         Throw $_
        #     }
        # }
    }
    process
    {
        if($Title)
        {
            $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
            $KeePassEntry.Strings.Set("Title", $SecureTitle)
        }

        if($UserName)
        {
            $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
            $KeePassEntry.Strings.Set("UserName", $SecureUser)
        }

        if($KeePassPassword)
        {
            $KeePassEntry.Strings.Set("Password", $KeePassPassword)
        }

        if($Notes)
        {
            $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
            $KeePassEntry.Strings.Set("Notes", $SecureNotes)
        }

        if($URL)
        {
            $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
            $KeePassEntry.Strings.Set("URL", $SecureURL)
        }
        
        ## If specified group is different than current group
        if($KeePassGroup.Uuid -ne $KeePassEntry.Uuid)
        {
            ## Make Full Copy of Entry
            $NewKeePassEntry = $KeePassEntry.CloneDeep()
            ## Assign New Uuid to CloneDeep
            $NewKeePassEntry.Uuid = New-Object KeePassLib.PwUuid($true)
            ## Add Clone to Specified group
            $KeePassGroup.AddEntry($NewKeePassEntry)
            ## Save for safety
            $KeePassConnection.Save($null)
            ## Delete previous entry
            $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry)
        }
        ## save database
        $KeePassConnection.Save($null)
    }
}

function Remove-KPEntry
{
    <#
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
            ValueFromPipelineByPropertyName
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

        $RecycleBin = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'Recycle Bin'
        $EntryDisplayName = "$($KeePassEntry.ParentGroup.GetFullPath('/',$false))/$($KeePassEntry.Strings.ReadSafe('Title'))"
        
        if ( $Force -or $PSCmdlet.ShouldProcess($($EntryDisplayName)))
        {
            if ( -not $Force -and (-not $RecycleBin -or $NoRecycle) )
            {
                if ( -not $PSCmdlet.ShouldContinue("Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.", "Do you want to continue to Permanently Delete this Entry: ($($EntryDisplayName))?"))
                {
                    break
                }
            }
        }
        else
        {
            break
        }
    }
    process
    {        
        if($RecycleBin -and -not $NoRecycle)
        {
            #Make Copy of the group to be recycled.
            $DeletedKeePassEntry = $KeePassEntry.CloneDeep()
            #Generate a new Uuid and update the copy fo the group
            $DeletedKeePassEntry.Uuid = (New-Object KeePassLib.PwUuid($true))
            #Add the copy to the recycle bin, with take ownership set to true
            $RecycleBin.AddGroup($DeletedKeePassEntry, $true)
            Write-Verbose -Message "[PROCESS] Group has been Recycled."    
        }
        
        #Deletes the specified group
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
    #>
    [CmdletBinding(DefaultParameterSetName = 'Full')]
    [OutputType('KeePassLib.PwGroup')]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ParameterSetName = 'Full'
        )]
        [Parameter(
            Position = 0,
            Mandatory,
            ParameterSetName = 'Partial'
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,
        
        [Parameter(
            Position = 1,
            Mandatory,
            ParameterSetName = 'Full',
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [string] $FullPath,
        
        [Parameter(
            Position = 1,
            Mandatory,
            ParameterSetName = 'Partial',
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [string] $GroupName
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
            [KeePassLib.PwGroup[]] $KeePassOutGroups = $null
            #hmm not sure what this $KpGroup variable is for...
            [KeePassLib.PwGroup] $KpGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject
            $KeePassGroups = $KeePassConnection.RootGroup.GetFlatGroupList()
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Get-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message "[BEGIN] $($ErrorNewPwGroupObject.ErrorRecord.Message)"
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
                if($_keepassGroup.GetFullPath("/", $false).Equals($FullPath))
                {
                    $KeePassOutGroups += $_keepassGroup
                }                   
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Partial')
        {
            foreach($_keepassGroup in $KeePassGroups)
            {
                if($_keepassGroup.Name.Equals($GroupName))
                {
                    $KeePassOutGroups += $_keepassGroup
                }
            }
        }
    }
    end{ $KeePassOutGroups }
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
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(
            Position = 1,
            Mandatory
        )]
        [ValidateNotNullorEmpty()]
        [string] $GroupName,

        [Parameter(
            Position = 2,
            Mandatory
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup
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
            [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            {
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message "[BEGIN] $($ErrorNewPwGroupObject.ErrorRecord.Message)"
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
        $KeePassParentGroup.AddGroup($KeePassGroup, $true)
        $KeePassConnection.Save($null)
    }
}

## Set/Update a KeePass Group
## needs parameter sets 
## checks to see if the changes are valid
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
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Paramter(
            Position = 1,
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(
            Position = 1,
            Mandatory = $false
        )]
        [ValidateNotNullorEmpty()]
        [string] $GroupName,

        [Parameter(
            Position = 2,
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup
    )
    begin
    {
        ## Check if database is open.
        if(-not $KeePassConnection.IsOpen)
        {
            Write-Warning -Message '[BEGIN] The KeePass Connection Sepcified is not open or does not exist.'
            break
        }
        # try
        # {
        #     [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject
        # }
        # catch
        # {
        #     Write-Warning -Message '[BEGIN] An error occured in the Add-KpGroup Cmdlet.'
        #     if($ErrorNewPwGroupObject)
        #     {
        #         Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
        #         Write-Warning -Message "[BEGIN] $($ErrorNewPwGroupObject.ErrorRecord.Message)"
        #         Throw $_
        #     }
        #     else
        #     {
        #         Write-Warning -Message '[BEGIN] An unhandled exception occured.'
        #         Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
        #         Throw $_
        #     }
        # }
    }
    process
    {
        
        if($GroupName)
        {
            $KeePassGroup.Name = $GroupName
        }
        
        if($KeePassParentGroup)
        {
            if($KeePassGroup.ParentGroup.Uuid -ne $KeePassParentGroup.Uuid)
            {
                $UpdatedKeePassGroup = $KeePassGroup.CloneDeep()
                $UpdatedKeePassGroup.Uuid = New-Object KeePassLib.PwUuid($true)
                $KeePassParentGroup.AddGroup($UpdatedKeePassGroup, $true)
                $KeePassConnection.Save($null)
                $KeePassGroup.ParentGroup.Entries.Remove($KeePassGroup)
            }
            
        }
        
        $KeePassConnection.Save($null)
    }
}

function Remove-KPGroup
{
    <#
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
            ValueFromPipelineByPropertyName
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
        [KeePassLib.PwGroup] $KeePassGroup,
        
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

        $RecycleBin = Get-KPGroup -KeePassConnection $KeePassConnection -FullPath 'Recycle Bin'
        
        if ( $Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/',$false))))
        {
            if ( -not $Force -and (-not $RecycleBin -or $NoRecycle) )
            {
                if ( -not $PSCmdlet.ShouldContinue("Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.", "Do you want to continue to Permanently Delete this Group: ($($KeePassGroup.GetFullPath('/',$false)))?"))
                {
                    break
                }
            }
        }
        else
        {
            break
        }
        ###Force only verses shouldprocess confirmation.
        # if (-not $Force)
        # {
        #     $caption = "Please Confirm"
        #     if( -not $RecycleBin -or $NoRecycle)
        #     {
        #         $Message = "Are you Sure You Want To Permanently Delete Group ($($KeePassGroup.GetFullPath('/',$false))) and all of its Entries and SubGroups." 
        #     }
        #     else
        #     {
        #         $Message = "Are you Sure You Want To Recycle Group ($($KeePassGroup.GetFullPath('/',$false))) and all of its Entries and SubGroups."    
        #     }  
            
        #     [int]$defaultChoice = 1
        #     $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Do the job."
        #     $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Do not do the job."
        #     $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        #     $choiceRTN = $host.ui.PromptForChoice($caption,$message, $options, $defaultChoice)

        #     if ( $choiceRTN -ne 1 )
        #     {
        #         Write-Warning -Message "Continueing with Operation."
        #     }
        #     else
        #     {
        #         Write-Warning -Message "Cancellation Requested. Aborting operation."
        #         Break
        #     }
        # }
    }
    process
    {
        if($RecycleBin -and -not $NoRecycle)
        {
            #Make Copy of the group to be recycled.
            $DeletedKeePassGroup = $KeePassGroup.CloneDeep()
            #Generate a new Uuid and update the copy fo the group
            $DeletedKeePassGroup.Uuid = (New-Object KeePassLib.PwUuid($true))
            #Add the copy to the recycle bin, with take ownership set to true
            $RecycleBin.AddGroup($DeletedKeePassGroup, $true)
            Write-Verbose -Message "[PROCESS] Group has been Recycled."    
        }
        
        #Deletes the specified group
        $IsRemoved = $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup)
        
        if(-not $IsRemoved)
        {
            Write-Warning -Message "[PROCESS] Unknown Error has occured. Failed to Remove Group ($($KeePassGroup.GetFullPath('/',$false)))"
            Throw "Failed to Remove Group $($KeePassGroup.GetFullPath('/',$false))"
        }
        else
        {
            Write-Verbose -Message "[PROCESS] Group ($($KeePassGroup.GetFullPath('/',$false))) has been Removed."
            $KeePassConnection.Save($null)
        }
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
    [OutputType([string])]
    param
    (
        [Parameter(Position=0,Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.Security.ProtectedString] $KeePassProtectedString
    )
    process
    {
        $KeePassProtectedString.ReadString()
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
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Position=0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $KeePassEntry
    )
    begin{ $KeePassPSOutObject = @() }
    process
    {

        foreach ($_keepassItem in $KeePassEntry)
        {
            $KeePassPsObject = New-Object -TypeName PSObject
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
            $KeePassPsObject | Add-Member -Name 'FullPath' -MemberType NoteProperty -Value $_keepassItem.ParentGroup.GetFullPath("/", $false)
            $KeePassPsObject | Add-Member -Name 'Title' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe("Title")
            $KeePassPsObject | Add-Member -Name 'UserName' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe("UserName")
            $KeePassPsObject | Add-Member -Name 'Password' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe("Password")
            $KeePassPsObject | Add-Member -Name 'URL' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe("URL")
            $KeePassPsObject | Add-Member -Name 'Notes' -MemberType NoteProperty -Value $_keepassItem.Strings.ReadSafe("Notes")
            $KeePassPSOutObject += $KeePassPsObject
        }
    }
    end{ $KeePassPSOutObject }
}

function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        Write-Debug -Message "Checking if KeePassLib is already loaded."
        $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()
        $KeePassAssembly = $LoadedAssemblies | Where-Object { $_.FullName -match "KeePassLib"}

        if($KeePassAssembly)
        {
            $KeePassAssemblyInfo = @{
                'Name' = $KeePassAssembly.FullName.Replace(' ','').Split(',')[0]
                'Version' = $KeePassAssembly.FullName.Replace(' ','').Split(',')[1].Split('=')[1]
                'Location' = $KeePassAssembly.Location
            }

            if($KeePassAssemblyInfo.Name -eq 'KeePassLib')
            {
                if($KeePassAssemblyInfo.Version -eq '2.30.0.15901')
                {
                    Write-Verbose -Message "KeePassLib has already been loaded, from: $($KeePassAssemblyInfo.Location)."
                    Write-Debug -Message "KeePassLib Assembly Name: $($KeePassAssemblyInfo.Name), Version: $($KeePassAssemblyInfo.Version)"
                    $KeePassAssemblyIsLoaded = $true
                }
                else
                {
                    Write-Debug -Message "A KeePassLib Assembly is loaded but it does not match the required version: '2.30.0.15901'"
                    Write-Debug -Message "Version Found: $($KeePassAssemblyInfo.Version)"
                    Write-Debug -Message "Will continue to load the correct version."
                }
            }
            else
            {
                Write-Debug -Message "No Loaded Assembly found for KeePassLib. Will Continue to load the Assembly."
            }
        }

        if(-not $KeePassAssemblyIsLoaded)
        {
            $EncodedCompressedFile = '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'
            $DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
            $UncompressedFileBytes = New-Object Byte[](252312)
            $DeflatedStream.Read($UncompressedFileBytes, 0, 252312) | Out-Null
            [Reflection.Assembly]::Load($UncompressedFileBytes)
        }
    }
}

#Source KpLib
Import-KPLibrary