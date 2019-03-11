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
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $KeePassPasswordObject
    )
    process
    {
        if(Test-Path -Path $Global:KeePassConfigurationFile)
        {
            $CheckIfExists = Get-KPPasswordProfile -PasswordProfileName $KeePassPasswordObject.ProfileName
            if($CheckIfExists)
            {
                Write-Warning -Message ('[PROCESS] A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName)
                Throw 'A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName
            }

            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($Global:KeePassConfigurationFile)
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

            $XML.Save($Global:KeePassConfigurationFile)
        }
        else
        {
            Write-Output 'No KeePass Database Configuration file exists. You can create one with the New-KeePassDatabaseConfiguration function.'
        }
    }

}
