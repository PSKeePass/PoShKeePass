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
                *This supports Tab completion as it will get all saved profiles.
        .INPUTS
            String
            Switch
        .OUTPUTS
            KeePassLib.Security.ProtectedString
    #>
    [CmdletBinding(DefaultParameterSetName = 'NoProfile')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName,

        [Parameter(Position = 0, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UpperCase,

        [Parameter(Position = 1, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $LowerCase,

        [Parameter(Position = 2, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Digits,

        [Parameter(Position = 3, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $SpecialCharacters,

        [Parameter(Position = 4, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Minus,

        [Parameter(Position = 5, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UnderScore,

        [Parameter(Position = 6, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Space,

        [Parameter(Position = 7, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Brackets,

        [Parameter(Position = 8, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $ExcludeLookALike,

        [Parameter(Position = 9, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $NoRepeatingCharacters,

        [Parameter(Position = 10, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $ExcludeCharacters,

        [Parameter(Position = 11, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [Int] $Length,

        [Parameter(Position = 12, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $SaveAs
    )
    begin
    {
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

            if(-not $PasswordProfileObject)
            {
                Write-Error -Message ('No KPPasswordProfile could be found with the specified Name: ' + $PasswordProfileName) -TargetObject $PasswordProfileName -Category ObjectNotFound -ErrorAction Stop
            }

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
        if($PSOut){Remove-Variable -Name PSOUT}
    }
}
