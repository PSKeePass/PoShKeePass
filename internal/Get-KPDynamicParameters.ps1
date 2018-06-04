function Get-KPDynamicParameters
{
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Int] $DBProfilePosition,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Int] $MasterKeyPosition,

        [Parameter(Position = 2)]
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
            $MasterKeyRuntimeParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($MasterKeyParameterName, [PSObject], $MasterKeyAttributeCollection)
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
