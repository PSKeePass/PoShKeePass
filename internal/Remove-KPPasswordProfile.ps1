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
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    begin
    {
    }
    process
    {
        if(-not (Test-Path -Path $Global:KeePassConfigurationFile))
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
