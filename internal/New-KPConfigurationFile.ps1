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
        [Parameter(Position = 0)]
        [Switch] $Force
    )
    process
    {
        if((Test-Path -Path $Global:KeePassConfigurationFile) -and -not $Force)
        {
            Write-Warning -Message '[PROCESS] A KeePass Configuration File already exists. Please rerun with -force to overwrite the existing configuration.'
            Write-Error -Message 'A KeePass Configuration File already exists.' -ea Stop
        }
        else
        {
            try
            {
                $Path = $Global:KeePassConfigurationFile

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
                Write-Warning -Message 'An exception occured while trying to create a new keepass configuration file.'
                Write-Error -ErrorRecord $_ -ea Stop
            }
        }
    }
}
