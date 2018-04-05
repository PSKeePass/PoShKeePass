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
        if ((Test-Path -Path $PSScriptRoot\..\KeePassConfiguration.xml) -and -not $Force)
        {
            Write-Warning -Message '[PROCESS] A KeePass Configuration File already exists. Please rerun with -force to overwrite the existing configuration.'
            Throw 'A KeePass Configuration File already exists.'
        }
        else
        {
            try
            {
                $Path = '{0}\..\KeePassConfiguration.xml' -f $PSScriptRoot

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
