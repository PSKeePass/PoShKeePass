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
        if (-not (Test-Path -Path $Global:KeePassConfigurationFile))
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
                        $XML.Load($Global:KeePassConfigurationFile)
                        $XML.Settings.DatabaseProfiles.Profile  | Where-Object { $_.Name -eq $DatabaseProfileName } | ForEach-Object { $xml.Settings.DatabaseProfiles.RemoveChild($_) } | Out-Null
                        $XML.Save($Global:KeePassConfigurationFile)
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
