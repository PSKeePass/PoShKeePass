function Remove-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to remove a specifed Password Profile.
        .DESCRIPTION
            Removes a specified password profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile to be delete from the config file.
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
        if (-not (Test-Path -Path $Global:KeePassConfigurationFile))
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
                    $XML.Load($Global:KeePassConfigurationFile)
                    $XML.Settings.PasswordProfiles.Profile  | Where-Object { $_.Name -eq $PasswordProfileName } | ForEach-Object { $xml.Settings.PasswordProfiles.RemoveChild($_) } | Out-Null
                    $XML.Save($Global:KeePassConfigurationFile)
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
