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
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()] [KeePassLib.Security.ProtectedString] $KeePassProtectedString
    )
    process
    {
        $KeePassProtectedString.ReadSafe()
    }
}
