function Remove-KPConnection
{
    <#
        .SYNOPSIS
            This Function Removes a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Removes a Connection to a KeePass Database.
        .EXAMPLE
            PS> Remove-KPConnection -KeePassConnection $DB

            This Example will Remove/Close a KeePass Database Connection using a pre-defined KeePass DB connection.
        .PARAMETER KeePassConnection
            This is the KeePass Connection to be Closed
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection
    )
    process
    {
        try
        {
            ## Close KeePass Database Connection
            if( $KeePassConnection.IsOpen)
            {
                $KeePassConnection.Close()
            }
            else
            {
                Write-Warning -Message '[PROCESS] The KeePass Database Specified is already closed or does not exist.'
                Throw 'The KeePass Database Specified is already closed or does not exist.'
            }

        }
        catch [Exception]
        {
            Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
            Throw $_
        }
    }
}
