function New-KPConnection
{
    <#
        .SYNOPSIS
            Creates an open connection to a Keepass database
        .DESCRIPTION
            Creates an open connection to a Keepass database using all available authentication methods
        .PARAMETER Database
            Path to the Keepass database (.kdbx file)
        .PARAMETER ProfileName
            Name of the profile entry
        .PARAMETER MasterKey
            Path to the keyfile (.key file) used to open the database
        .PARAMETER Keyfile
            Path to the keyfile (.key file) used to open the database
        .PARAMETER UseWindowsAccount
            Use the current windows account as an authentication method
    #>
    [CmdletBinding(DefaultParameterSetName = 'Profile')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $Database,

        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'CompositeKey')]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'Profile')]
        [AllowNull()]
        [PSObject] $MasterKey,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $KeyPath,

        [Parameter(Position = 3, ParameterSetName = 'CompositeKey')]
        [Switch] $UseWindowsAccount
    )
    process
    {
        ## Create KP Database Object
        try
        {
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }
        catch
        {
            Import-KPLibrary
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }

        ## Create KP CompositeKey Object
        $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

        ## Validate MasterKey Type
        if(($MasterKey -isnot [PSCredential]) -and ($MasterKey -isnot [SecureString]) -and $MasterKey)
        {
            Write-Error -Message ('[PROCESS] The MasterKey of type: ({0}). Is not Supported Please supply a MasterKey of Types (SecureString or PSCredential).' -f $($MasterKey.GetType().Name)) -Category InvalidType -TargetObject $MasterKey -RecommendedAction 'Provide a MasterKey of Type PSCredential or SecureString'
        }

        ## Get Profile Values
        if($PSCmdlet.ParameterSetName -eq 'Profile')
        {
            $KeepassConfigurationObject = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName

            if(-not $KeepassConfigurationObject)
            {
                throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            }

            $Database = $KeepassConfigurationObject.DatabasePath
            if($KeepassConfigurationObject.KeyPath -ne '' ){ $KeyPath = $KeepassConfigurationObject.KeyPath }
            [Switch] $UseWindowsAccount = $KeepassConfigurationObject.UseNetworkAccount
            [Switch] $UseMasterKey = $KeepassConfigurationObject.UseMasterKey

            ## Prompt for MasterKey if specified in the profile and was not provided.
            if($UseMasterKey -and -not $MasterKey)
            {
                $MasterKey = $Host.ui.PromptForCredential('KeePassCredential', 'Please enter your KeePass password.', 'KeePass', 'KeePass')
            }
        }
        ## Added this separation for easier future Management.
        elseif($PSCmdlet.ParameterSetName -eq 'CompositeKey')
        {
            $UseMasterKey = if($MasterKey){ $true }
        }

        ## Handle if the master key is a PSCredential
        if($MasterKey -is [PSCredential])
        {
            [SecureString] $MasterKey = $MasterKey.Password
        }

        ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
        $DatabaseItem = Get-Item -Path $Database -ErrorAction Stop

        ## Start Building CompositeKey
        ## Order in which the CompositeKey is created is important and must follow the order of : MasterKey, KeyFile, Windows Account
        if($UseMasterKey)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterKey)))))
        }

        if($KeyPath)
        {
            try
            {
                ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
                $KeyPathItem = Get-Item $KeyPath -ErrorAction Stop
                $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpKeyfile($KeyPathItem.FullName)))
            }
            catch
            {
                ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
                Write-Warning ('Could not read the specfied Key file [{0}].' -f $KeyPathItem.FullName)
            }
        }

        if($UseWindowsAccount)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
        }

        ## Create IOConnection Object
        $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
        $IOInfo.Path = $DatabaseItem.FullName

        ## We currently are not using a status logger hence the null.
        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

        ## Connect, Open and Return Database Object
        $DatabaseObject.Open($IOInfo, $CompositeKey, $IStatusLogger) | Out-Null
        $DatabaseObject

        ##Exception : I will want to handle this error in a more user friendly error, as is the style of the rest of this module.
        if(-not $DatabaseObject.IsOpen)
        {
            Throw 'InvalidDatabaseConnectionException : The database is not open.'
        }
    }
}
