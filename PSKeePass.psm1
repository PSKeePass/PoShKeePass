<# 

    This Module is based on the work of Jason Fossen at Sans.org (https://cyber-defense.sans.org/blog/2015/08/13/powershell-for-keepass-sample-script)
    
    It´s intent is to make the usage of KeePass as a credential database inside PowerShell scripts as easy
    as possible. Please be aware that you should use SecureStrngs, PSCredential objects and Event-Log encryption to keep you secrets save.
    More info at:
    - Protected Eventlog at https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
    - https://blogs.msdn.microsoft.com/powershell/2013/12/16/powershell-security-best-practices/
#> 

function Get-KeePassEntry { 
  <#

      .SYNOPSIS
      Find and return a KeePass entry from a group based on entry title.
 
      .DESCRIPTION
      After opening a KeePass database, provide the function with the name
      of a top-level group in KeePass (cannot be a nested subgroup) and the
      title of a unique entry in that group. The function returns the username,
      password, URL and notes for the entry by default, all in plaintext.
      Alternatively, just a PSCredential object may be returned instead; an
      object of the same type returned by the Get-Credential cmdlet. 

      .PARAMETER DBCredential
      The Credentials to open the KeePass Database must be provided as PSCredential object.
      The Username of the PSCredential object is a dummy name and is only needed to create 
      the PSCredential obejct. The password however has to be the MasterKey of your KeePass
      database.
 
      .PARAMETER TopLevelGroupName
      Name of the KeePass folder. Must be top level, cannot be nested, and
      must be unique, i.e., no other groups/folders of the same name.
 
      .PARAMETER Title
      The title of the entry to return. Must be unique.

      .PARAMETER DBPath
      Alternative path of a KeePass Database File. 
      If no value is provieded, the default database defined with Set-KeePassConfiguration
      will be used.
 
      .PARAMETER AsSecureStringCredential
      Switch to return a PSCredential object with just the username and
      password as a secure string. Username cannot be blank. The object
      is of the same type returned by the Get-Credential cmdlet.

      .EXAMPLE
      Get-KeePassEntry -DBCredential (get-credential) -TopLevelGroupName Internet -Title MyTestEntry

      Description:
      Get´s a KeePass Database entry with Title "MyTestEntry", located in the group "Internet" from the default KeePass Database with all values in cleartext.

      Output:
      GAC    Version        Location
      ---    -------        --------
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe

      Title    : MyTestEntry
      UserName : TestUser
      Password : TestPassword
      URL      :
      Notes    :

      .EXAMPLE
      Get-KeePassEntry -DBCredential $mycred -TopLevelGroupName Internet -Title MyTestEntry -AsSecureStringCredential

      Description:
      Get´s a KeePass Database entry with Title "MyTestEntry", located in the group "Internet" from the default KeePass Database as a PSCredential Object.

      Output:
      GAC    Version        Location                                                                                                                                                                
      ---    -------        --------                                                                                                                                                                
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe                                                                                                              

      UserName : TestUser
      Password : System.Security.SecureString
  #>
  param (
    
    [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
    Position=0)]
    [System.Management.Automation.PSCredential]$DBcredential,

    [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
    Position=1)]
    [string]$TopLevelGroupName,

    [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
    Position=2)]
    [string]$Title,
    [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
    Position=3)]
    [string]$DBPath,
    [switch] $AsSecureStringCredential


  )


  #Read the global configuration
  [xml]$Configuration = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
  $KPProgramfolder = $Configuration.Settings.KeePassSettings.KPProgramFolder
  $DBDefaultpathPath = $Configuration.Settings.KeePassSettings.DBDefaultpathPath

  #Check if a KeePass Database File path has been provided. If not, set standardpath defined in KeePassConfiguration.xml
  If (!($DBPath) ) {$DBPath = $DBDefaultpathPath}
 
  #Check if KeePass Database exists

  if(!(test-path $DBPath))
  {$Errorcode = 'The provided database path does not exist. Please check your settings. You can define a default Database with Set-KeePassConfiguration'
    Write-Output "$Errorcode"
  break}
  # Load the classes from KeePass.exe:
  $KeePassEXE = Join-Path -Path $KPProgramFolder -ChildPath 'KeePass.exe'
  [Reflection.Assembly]::LoadFile($KeePassEXE)

  ###########################################################################
  # To open a KeePass database, the decryption key is required, and this key
  # may be a constructed from a password, key file, Windows user account,
  # and/or other information sources. In the current implementation, only the
  # password option is available.
  ###########################################################################
 
  # $CompositeKey represents a key, possibly constructed from multiple sources of data.
  # The other key-related objects are added to this composite key.
  $CompositeKey = New-Object -TypeName KeePassLib.Keys.CompositeKey #From KeePass.exe
 
  # A password can be added to a composite key.
  $Password = ($DBcredential.getnetworkcredential()).password
  $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($Password)
 
  # Add the Windows user account key to the $CompositeKey, if necessary:
  ##$CompositeKey.AddUserKey( $KcpUserAccount )
  $CompositeKey.AddUserKey( $KcpPassword )
  #$CompositeKey.AddUserKey( $KcpKeyFile )
 
  ###########################################################################
  # To open a KeePass database, the path to the .KDBX file is required.
  ###########################################################################
 
  $IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
  $IOConnectionInfo.Path = $DBPath
 
  ###########################################################################
  # To open a KeePass database, an object is needed to record status info.
  # In this case, the progress status information is ignored.
  ############################################################################
 
  $StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
 
  ###########################################################################
  # Open the KeePass database with key, path and logger objects.
  # $PwDatabase represents a KeePass database.
  ############################################################################
  try{ 
    $PwDatabase = New-Object -TypeName KeePassLib.PwDatabase #From KeePass.exe
    $PwDatabase.Open($IOConnectionInfo, $CompositeKey, $StatusLogger)
  }
  catch {
    $Errorcode = 'Error opening the KeePass Password database. Make sure the credentials and KeePass Database filepath are correct.'
    Write-Output $Errorcode
    throw
  }

  try { 

    # This only works for a top-level group, not a nested subgroup (lazy).
    $PwGroup = @( $PwDatabase.RootGroup.Groups | Where-Object { $_.name -eq $TopLevelGroupName } )
 
    # Confirm that one and only one matching group was found
    if ($PwGroup.Count -eq 0) { $Errorcode = "ERROR: $TopLevelGroupName group not found" 
    Throw }
    elseif ($PwGroup.Count -gt 1) { $Errorcode = "ERROR: Multiple groups named $TopLevelGroupName" 
    Throw $Errorcode}
 
    # Confirm that one and only one matching title was found
    $entry = @( $PwGroup[0].GetEntries($True) | Where-Object { $_.Strings.ReadSafe('Title') -eq $Title } )
    if ($entry.Count -eq 0) { $Errorcode = "ERROR: $Title not found" 
      Throw ;
    }
    elseif ($entry.Count -gt 1) { $Errorcode = "ERROR: Multiple entries named $Title"
    Throw }
 
    if ($AsSecureStringCredential)
    {
      $secureString = ConvertTo-SecureString -String ($entry[0].Strings.ReadSafe('Password')) -AsPlainText -Force
      [string] $username = $entry[0].Strings.ReadSafe('UserName')
      if ($username.Length -eq 0){ $Errorcode = 'ERROR: Cannot create credential, username is blank'
      throw }
      New-Object System.Management.Automation.PSCredential($username, $secureString)
    }
    else
    {
      $output = '' | Select-Object Title,UserName,Password,URL,Notes
      $output.Title = $entry[0].Strings.ReadSafe('Title')
      $output.UserName = $entry[0].Strings.ReadSafe('UserName')
      $output.Password = $entry[0].Strings.ReadSafe('Password')
      $output.URL = $entry[0].Strings.ReadSafe('URL')
      $output.Notes = $entry[0].Strings.ReadSafe('Notes')
      $output


    }
  }
  catch {Write-output $Errorcode
  }

  finally { 
    #Close database
    $PwDatabase.Close()
    #Clear-Variable Output
    Clear-Variable Password
    Clear-Variable KcpPassword
  }
}

function New-KeePassEntry
{
  <#
      .SYNOPSIS
      Adds a new KeePass entry.
 
      .DESCRIPTION
      Adds a new KeePass entry. The name
      of a top-level group/folder in KeePass and an entry title are mandatory,
      but all other arguments are optional. The group/folder must be at the top
      level in KeePass, i.e., it cannot be a nested subgroup. The username + password
      have to be provided as a PSCredential object. The secure string from the PSCredential 
      is converted to plaintext and then saved to the KeePass entry. The PSCredential object
      is normally created using the Get-Credential cmdlet.
 
      .PARAMETER DBCredential
      The Credentials to open the KeePass Database must be provided as PSCredential object.
      The Username of the PSCredential object is a dummy name and is only needed to create 
      the PSCredential obejct. The password however has to be the MasterKey of your KeePass
      database.
 
      .PARAMETER TopLevelGroupName
      Name of the KeePass folder (mandatory). Must be top level, cannot be
      nested, and must be unique, i.e., no other groups of the same name.
 
      .PARAMETER Title
      The title of the entry to add (mandatory). If an entry with the same title is already
      present in the provided TopLevelGroup, the new entry will not be created.
 
      .PARAMETER DBPath
      Alternative path of a KeePass Database File. 
      If no value is provieded, the default database defined with Set-KeePassConfiguration
      will be used.

      .PARAMETER EntryCredential
      A PowerShell secure string credential object, typically
      created with the Get-Credential cmdlet. The KeePass entry
      will be created using the user name and plaintext password of
      the PSCredential object. Other data, such as Notes or URL, may
      still be added. The KeePass entry will have the plaintext password
      from the PSCredential in the KeePass GUI, not the secure string.
 
      .PARAMETER URL
      The URL of the entry to add.
 
      .PARAMETER Notes
      The Notes of the entry to add.

      .EXAMPLE

      New-KeePassEntry -DBcredential $mycred -TopLevelGroupName Internet -Title NewTestEntry -EntryCredential $NewEntryCred -URL www.testurl.com -Notes "This is a test entry"

      Description:
      Creates a new entry with Username, password, URL and notes in the Internet TopLevelGroup of the default KeePass Database (defined with Set-KeePassConfiguration).
      $NewEntryCred has been created with get-credential.

      Output:

      GAC    Version        Location
      ---    -------        --------
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
      Entry NewTestEntry successfully created

      .EXAMPLE

      New-KeePassEntry -DBcredential $mycred -TopLevelGroupName Internet -Title NewTestEntry -EntryCredential $NewEntryCred -DBPath C:\TEMP\Test-Database.kdbx

      Description:
      Creates a new entry with Username and password in the Internet TopLevelGroup in the KeePass Database provided with $DBPath. 
      $NewEntryCred has been created with get-credential.

      Output:
      GAC    Version        Location
      ---    -------        --------
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
      Entry NewTestEntry successfully created
    
  #>
 
  [CmdletBinding()]
  Param
  (
    #[Parameter(Mandatory=$true)] [KeePassLib.PwDatabase] $PwDatabase,
    [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
    Position=0)]
    [System.Management.Automation.PSCredential]$DBcredential,
    [string]$DBPath,
    [Parameter(Mandatory=$true)] [String] $TopLevelGroupName,
    [Parameter(Mandatory=$true)] [String] $Title,
    [Parameter(Mandatory=$false)] [System.Management.Automation.PSCredential] $EntryCredential,
    [String] $URL,
    [String] $Notes
  )


  #Check if an entry with the same name already exists in the same database in the same TopLevelGroup

  if ($DBPath)
  {$Entryexists = (get-KeePassEntry -DBcredential $DBcredential -Title $Title -TopLevelGroupname $TopLevelGroupName -DBPath $DBPath) }

  else {$Entryexists = (get-KeePassEntry -DBcredential $DBcredential -Title $Title -TopLevelGroupname $TopLevelGroupName)}
  Try { 
    #Read the global configuration
    [xml]$Configuration = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
    $KPProgramfolder = $Configuration.Settings.KeePassSettings.KPProgramFolder
    $DBDefaultpathPath = $Configuration.Settings.KeePassSettings.DBDefaultpathPath
  

    #Check if a KeePass Database File path has been provided. If not, set standardpath defined in KeePassConfiguration.xml
    If (!($DBPath) ) {$DBPath = $DBDefaultpathPath}
 
    # Load the classes from KeePass.exe:
    $KeePassEXE = Join-Path -Path $KPProgramFolder -ChildPath 'KeePass.exe'
    [Reflection.Assembly]::LoadFile($KeePassEXE)

    ###########################################################################
    # To open a KeePass database, the decryption key is required, and this key
    # may be a constructed from a password, key file, Windows user account,
    # and/or other information sources. In the current implementation, only the
    # password option is available.
    ###########################################################################
 
    # $CompositeKey represents a key, possibly constructed from multiple sources of data.
    # The other key-related objects are added to this composite key.
    $CompositeKey = New-Object -TypeName KeePassLib.Keys.CompositeKey #From KeePass.exe
 
    # A password can be added to a composite key.
    $Password = ($DBcredential.getnetworkcredential()).password
    $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($Password)
 
    # Add the Windows user account key to the $CompositeKey, if necessary:
    ##$CompositeKey.AddUserKey( $KcpUserAccount )
    $CompositeKey.AddUserKey( $KcpPassword )
    #$CompositeKey.AddUserKey( $KcpKeyFile )
 
    ###########################################################################
    # To open a KeePass database, the path to the .KDBX file is required.
    ###########################################################################
 
    $IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
    $IOConnectionInfo.Path = $DBPath
 
    ###########################################################################
    # To open a KeePass database, an object is needed to record status info.
    # In this case, the progress status information is ignored.
    ############################################################################
 
    $StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
 
    ###########################################################################
    # Open the KeePass database with key, path and logger objects.
    # $PwDatabase represents a KeePass database.
    ############################################################################
    try{ 
      $PwDatabase = New-Object -TypeName KeePassLib.PwDatabase #From KeePass.exe
      $PwDatabase.Open($IOConnectionInfo, $CompositeKey, $StatusLogger)
    }
    catch {
      $Errorcode = 'Error opening the KeePass Password database. Make sure the credentials and KeePass Database filepath are correct.'
    throw $Errorcode}

    #. .\openKPDB.ps1
    # This only works for a top-level group, not a nested subgroup:
    $PwGroup = @( $PwDatabase.RootGroup.Groups | Where-Object { $_.name -eq $TopLevelGroupName } )
 
    # Confirm that one and only one matching group was found
    if ($PwGroup.Count -eq 0) { $Errorcode = "ERROR: $TopLevelGroupName group not found" 
    Throw }
    elseif ($PwGroup.Count -gt 1) { $Errorcode = "ERROR: Multiple groups named $TopLevelGroupName" 
    Throw }
 
    #check if an entry with this title in this group already exists

    #$Entryexists = (get-KeePassEntry -DBcredential $DBcredential -Title $Title -TopLevelGroupname $TopLevelGroupName)
    if ($Entryexists -like 'ERROR: * not found') 
    { 

      #Use PSCredential, if provided, for username and password:
      #if ($EntryCredential)
      #{
      $UserName = $EntryCredential.UserName
      $Entrypassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($EntryCredential.Password))
      #}
 
      # The $True arguments allow new UUID and timestamps to be created automatically:
      $PwEntry = New-Object -TypeName KeePassLib.PwEntry( $PwGroup[0], $True, $True )
 
      # Protected strings are encrypted in memory:
      $pTitle = New-Object KeePassLib.Security.ProtectedString($True, $Title)
      $pUser = New-Object KeePassLib.Security.ProtectedString($True, $UserName)
      $pPW = New-Object KeePassLib.Security.ProtectedString($True, $EntryPassword)
      $pURL = New-Object KeePassLib.Security.ProtectedString($True, $URL)
      $pNotes = New-Object KeePassLib.Security.ProtectedString($True, $Notes)
 
      $PwEntry.Strings.Set('Title', $pTitle)
      $PwEntry.Strings.Set('UserName', $pUser)
      $PwEntry.Strings.Set('Password', $pPW)
      $PwEntry.Strings.Set('URL', $pURL)
      $PwEntry.Strings.Set('Notes', $pNotes)
 
      $PwGroup[0].AddEntry($PwEntry, $True)
 
      # Notice that the database is automatically saved here!
      $StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
      $PwDatabase.Save($StatusLogger)
      Write-Output "Entry $Title successfully created"
    } 

    Else {$Errorcode = 'An Entry with this Title already exists in the provided group'
    Throw $Errorcode}
  }


  Catch {
    Write-output $Errorcode
  }
  Finally {
  
    $PwDatabase.close()
    if($Entrypassword){ Clear-Variable Entrypassword}
    if($Password) {Clear-Variable Password}
    if($output) {Clear-Variable output}
    if($PwDatabase) {Clear-Variable PwDatabase}
    if($pPW) {Clear-Variable pPW}
  }

}

function Set-KeePassEntry
{
  <#
      .SYNOPSIS
      Sets single or multiple properties of a KeePass entry based on the tirle of
      the entry.
 
      .DESCRIPTION
      Adds or changes properties of an existing KeePass entry. The name
      of a top-level group/folder in KeePass and an entry title are mandatory,
      but all other arguments are optional. The group/folder must be at the top
      level in KeePass, i.e., it cannot be a nested subgroup. The username + password
      must be provided as a PSCredential object.
      in which case the secure string from the PSCredential is converted to
      plaintext and then saved to the KeePass entry. The PSCredential object
      is normally created using the Get-Credential cmdlet.
 
      .PARAMETER DBCredential
      The Credentials to open the KeePass Database must be provided as PSCredential object.
      The Username of the PSCredential object is a dummy name and is only needed to create 
      the PSCredential obejct. The password however has to be the MasterKey of your KeePass
      database.
 
      .PARAMETER TopLevelGroupName
      Name of the KeePass folder (mandatory). Must be top level, cannot be
      nested, and must be unique, i.e., no other groups of the same name.
 
      .PARAMETER Title
      The title of the entry to add (mandatory). If an entry with the same title is already
      present in the provided TopLevelGroup, the new entry will not be created.
 
      .PARAMETER DBPath
      Alternative path of a KeePass Database File. 
      If no value is provieded, the default database defined with Set-KeePassConfiguration
      will be used.

      .PARAMETER EntryCredential
      A PowerShell secure string credential object, typically
      created with the Get-Credential cmdlet. The KeePass entry
      will be created using the user name and plaintext password of
      the PSCredential object. Other data, such as Notes or URL, may
      still be added. The KeePass entry will have the plaintext password
      from the PSCredential in the KeePass GUI, not the secure string.
      .PARAMETER PwDatabase
      The previously-opened KeePass database object (mandatory).
 
      .PARAMETER URL
      The URL of the entry to add. If no new URL is provided, the existing value will be kept.
 
      .PARAMETER Notes
      The Notes of the entry to add. If no new notes are provided, the existing value will be kept.

      .PARAMETER appendnotes
      Switch to decide if the provided notes should overwrite the existing entry or append the new notes to the 

      .EXAMPLE
      Set-KeePassEntry -DBcredential $mycred -TopLevelGroupName Internet -Title NewTestEntry -EntryCredential $NewEntryCred -DBPath C:\TEMP\Test-Database.kdbx

      Description: Set´s new values for username and password that are provided as a PSCredential object in the NewTestEntry 
      entry in the Internet TopLevelGroup of the KeePass database provided with the DBPath parameter.
      $NewentryCred can be created with Get-Credential.

      Output:
      GAC    Version        Location
      ---    -------        --------
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
      Entry NewTestEntry has been successfully set

      .EXAMPLE
      Set-KeePassEntry -DBcredential $mycred -TopLevelGroupName Internet -Title TestEntry -EntryCredential $NewEntryCred -URL "www.test.com" -notes "TestNotes for TestEntry entry"

      Description: 
      Set´s new values for username and password that are provided as a PSCredential object and new values for the URL and notes in the TestEntry 
      entry in the Internet TopLevelGroup of the default KeePass database. The default KeePass database can be set with Set-KeePassConfiguration.
      $NewentryCred can be created with Get-Credential.

      Output:
      GAC    Version        Location
      ---    -------        --------
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
      Entry TestEntry has been successfully set

      .EXAMPLE
      Set-KeePassEntry -DBcredential $mycred -TopLevelGroupName Internet -Title TestEntry -EntryCredential $NewEntryCred -URL "www.test.com" -notes "TestNotes for TestEntry entry" -appendnotes

      Description: 
      Set´s new values for username and password that are provided as a PSCredential object and new values for the URL and notes in the TestEntry 
      entry in the Internet TopLevelGroup of the default KeePass database. The new value for notes is appended to the existing notes of the entry.
      The default KeePass database can be set with Set-KeePassConfiguration. $NewentryCred can be created with Get-Credential.

      Output:
      GAC    Version        Location
      ---    -------        --------
      False  v2.0.50727     C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
      Entry TestEntry has been successfully set


  #>
 
  [CmdletBinding()]
  Param
  (
    #[Parameter(Mandatory=$true)] [KeePassLib.PwDatabase] $PwDatabase,
    [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
    Position=0)]
    [System.Management.Automation.PSCredential]$DBcredential,
    [string]$DBPath,
    [Parameter(Mandatory=$true)] [String] $TopLevelGroupName,
    [Parameter(Mandatory=$true)] [String] $Title,
    [Parameter(Mandatory=$true)] [System.Management.Automation.PSCredential] $EntryCredential,
    [String] $URL,
    [String] $Notes,
    [switch] $appendnotes
  )

  #Check if an entry with the same name already exists in the same database in the same TopLevelGroup
  if ($DBPath)
  {$Entryexists = (get-KeePassEntry -DBcredential $DBcredential -Title $Title -TopLevelGroupname $TopLevelGroupName -DBPath $DBPath) }

  else {$Entryexists = (get-KeePassEntry -DBcredential $DBcredential -Title $Title -TopLevelGroupname $TopLevelGroupName)}
    
      
  Write-Verbose "$Entryexists"
  if ($Entryexists -like 'ERROR: * not found')
  {$Errorcode = "No entry with title $Title exists"
  Write-Output "$Errorcode"}
    
  else{ 

    Try { 
      #Read the global configuration
      [xml]$Configuration = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
      $KPProgramfolder = $Configuration.Settings.KeePassSettings.KPProgramFolder
      $DBDefaultpathPath = $Configuration.Settings.KeePassSettings.DBDefaultpathPath
  

      #Check if a KeePass Database File path has been provided. If not, set standardpath defined in KeePassConfiguration.xml
      If (!($DBPath) ) {$DBPath = $DBDefaultpathPath}
 
      # Load the classes from KeePass.exe:
      $KeePassEXE = Join-Path -Path $KPProgramFolder -ChildPath 'KeePass.exe'
      [Reflection.Assembly]::LoadFile($KeePassEXE)

      ###########################################################################
      # To open a KeePass database, the decryption key is required, and this key
      # may be a constructed from a password, key file, Windows user account,
      # and/or other information sources. In the current implementation, only the
      # password option is available.
      ###########################################################################
 
      # $CompositeKey represents a key, possibly constructed from multiple sources of data.
      # The other key-related objects are added to this composite key.
      $CompositeKey = New-Object -TypeName KeePassLib.Keys.CompositeKey #From KeePass.exe
 
      # A password can be added to a composite key.
      $Password = ($DBcredential.getnetworkcredential()).password
      $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($Password)
 
      # Add the Windows user account key to the $CompositeKey, if necessary:
      ##$CompositeKey.AddUserKey( $KcpUserAccount )
      $CompositeKey.AddUserKey( $KcpPassword )
      #$CompositeKey.AddUserKey( $KcpKeyFile )
 
      ###########################################################################
      # To open a KeePass database, the path to the .KDBX file is required.
      ###########################################################################
 
      $IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
      $IOConnectionInfo.Path = $DBPath
 
      ###########################################################################
      # To open a KeePass database, an object is needed to record status info.
      # In this case, the progress status information is ignored.
      ############################################################################
 
      $StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
 
      ###########################################################################
      # Open the KeePass database with key, path and logger objects.
      # $PwDatabase represents a KeePass database.
      ############################################################################
      try{ 
        $PwDatabase = New-Object -TypeName KeePassLib.PwDatabase #From KeePass.exe
        $PwDatabase.Open($IOConnectionInfo, $CompositeKey, $StatusLogger)
      }
      catch {
        $Errorcode = 'Error opening the KeePass Password database. Make sure the credentials and KeePass Database filepath are correct.'
      throw $Errorcode}

      #try { 

        # This only works for a top-level group, not a nested subgroup (lazy).
        $PwGroup = @( $PwDatabase.RootGroup.Groups | Where-Object { $_.name -eq $TopLevelGroupName } )
 
        # Confirm that one and only one matching group was found
        if ($PwGroup.Count -eq 0) { $Errorcode = "ERROR: $TopLevelGroupName group not found" 
        Throw }
        elseif ($PwGroup.Count -gt 1) { $Errorcode = "ERROR: Multiple groups named $TopLevelGroupName" 
        Throw $Errorcode}
 
        # Confirm that one and only one matching title was found
        $entry = @( $PwGroup[0].GetEntries($True) | Where-Object { $_.Strings.ReadSafe('Title') -eq "$Title" } )
        if ($entry.Count -eq 0) { $Errorcode = "ERROR: $Title not found" 
          Throw ;
        }
        elseif ($entry.Count -gt 1) { $Errorcode = "ERROR: Multiple entries named $Title"
        Throw }
 
        $output = '' | Select-Object Title,UserName,Password,URL,Notes,UUID
        $output.Title = $entry[0].Strings.ReadSafe('Title')
        $output.UserName = $entry[0].Strings.ReadSafe('UserName')
        $output.Password = $entry[0].Strings.ReadSafe('Password')
        $output.URL = $entry[0].Strings.ReadSafe('URL')
        $output.Notes = $entry[0].Strings.ReadSafe('Notes')
        $output.UUID = $entry[0].UUID
      

      #}
      # }
    #  catch {Write-Output $Errorcode
  
     # }    
  
    
  
      #Assign the changed properties to the entry 
      $UserName = $EntryCredential.UserName
      #get password from credentials object
      $Entrypassword = $EntryCredential.GetNetworkCredential().Password

      #prepare object to set new values if new values are provided
      # The $True arguments allow new UUID and timestamps to be created automatically:
      $NewEntry = New-Object -TypeName KeePassLib.PwEntry( $PwGroup[0], $True, $True )
 
      # Protected strings are encrypted in memory:
      $pTitle = New-Object KeePassLib.Security.ProtectedString($True, $Title)

      if (!($output.username -eq $UserName ))
      { 
        $pUser = New-Object KeePassLib.Security.ProtectedString($True, $UserName)
      }
      Else { 
        $pUser = New-Object KeePassLib.Security.ProtectedString($True, $Output.username)
      }
      if (!($output.Password -eq $EntryPassword))
      { $pPW = New-Object KeePassLib.Security.ProtectedString($True, $EntryPassword)
      }
      else 
      {
        $pPW = New-Object KeePassLib.Security.ProtectedString($True, $Output.Password)
      }

      if (!($Url))
      {
        $pURL = New-Object KeePassLib.Security.ProtectedString($True, $Output.url)
      }
      else
      {
        $pURL = New-Object KeePassLib.Security.ProtectedString($True, $url)
      }

      if (!($Notes))
      {

        $pNotes = New-Object KeePassLib.Security.ProtectedString($True, $output.notes)
      }
      else
      {
        if ($appendnotes) {
          $Notes = $output.Notes + ' ' + $notes
          $pNotes = New-Object KeePassLib.Security.ProtectedString($True, $Notes)
        }
        else {
          $pNotes = New-Object KeePassLib.Security.ProtectedString($True, $Notes)
        }
      }
 
      $NewEntry.Strings.Set('Title', $pTitle)
      $NewEntry.Strings.Set('UserName', $pUser)
      $NewEntry.Strings.Set('Password', $pPW)
      $NewEntry.Strings.Set('URL', $pURL)
      $NewEntry.Strings.Set('Notes', $pNotes)
      $NewEntry.UUID = $output.UUID


      Write-Verbose $Entry[0].Strings.Readsafe('URL')
      Write-Verbose $Entry[0].Strings.Readsafe('Title')

      $entry[0].AssignProperties($NewEntry,$true,$true,$true)

  
      # Notice that the database is automatically saved here!
      $StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
      $PwDatabase.Save($StatusLogger)
    
      Write-Output "Entry $Title has been successfully set"
      #}
   
    }


    Catch {
      Write-output $Errorcode
    }
    Finally {

      $PwDatabase.close()

      if($Entrypassword) {Clear-Variable Entrypassword}
      if($Password) {Clear-Variable Password}
      if($Output){Clear-Variable output}
      if($PWDatabase){Clear-Variable PWDatabase}
      if($pWp){Clear-Variable pPw}
    }
  }
  

}

function Set-KeePassConfiguration
{
  <#
      .SYNOPSIS
      Sets the configuration for the PowerShell KeePass Module.
      .LONGDESCRIPTION
      Adds the entries KPProgramfolder and DBDefaultpathPath to the KeePassConfiguration.xml
      located in the modules root folder.
      .PARAMETER DBDefaultpathPath
      The path to the default KeePass Database file.
      e.g. C:\KeePassDBs\mytest.kdbx
      The default Databasfile can be overwritten by the Cmdlets
      Get-KeePassEntry, New-KeePassEntry, Set-KeePassEntry by defining the
      DBPath parameter.

      .EXAMPLE
      Set-KeePassConfiguration -DBDefaultpathPath C:\TEMP\Test-Database.kdbx -KPProgramFolder 'C:\Program Files (x86)\KeePass Password Safe 2\'
      
      Description: Creates a new KeePassConfiguration.xml in the current PowerShell module folder if there is no existing KeePassConfiguration.xml.
      If the KeePassConfiguration.xml already exists it will be overwritten.
    
      Output:
      KeePass configuration successfully updated


  #>
  param([string]$DBDefaultpathPath,
    [string]$KPProgramFolder
  )

  #Check if there already is a KeePassConfiguration.xml which can be used / overwritten
  if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
  { 

    [xml]$XML = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
    $xml.Settings.KeePassSettings.DBDefaultpathPath = $DBDefaultpathPath
    $xml.Settings.KeePassSettings.KPProgramFolder = $KPProgramFolder
    $xml.Save("$PSScriptRoot\KeePassConfiguration.xml")

    Write-Output 'KeePass configuration successfully updated'

  }

  else {
  
    $Path = "$PSScriptRoot\KeePassConfiguration.xml"
  
    $XML = New-Object System.Xml.XmlTextWriter($Path,$null)
    $XML.Formatting = 'Indented'
    $XML.Indentation = 1
    $XML.IndentChar = "`t"

    $XML.WriteStartDocument()
    $XML.WriteProcessingInstruction('xml-stylesheet', "type='text/xsl' href='style.xsl'")

    $XML.WriteStartElement('Settings')
    $XML.WriteStartElement('KeePassSettings')
    $XML.WriteElementString('DBDefaultpathPath',"$DBDefaultpathPath")
    $XML.WriteElementString('KPProgramFolder',"$KPProgramFolder")
    $XML.WriteEndElement()
    $XML.WriteEndElement()

    $XML.WriteEndDocument()
    $xml.Flush()
    $xml.Close()

    Write-Output 'KeePass configuration successfully created. The update, run Set-KeePassConfiguration again'
  }
      
}

function Get-KeePassConfiguration {

  <#
      .SYNOPSIS
      Reads the current KeePassConfiguration and displays values for DBDefaultpathPath and KPProgramfolder for the PowerShell KeePass Module.
      .LONGDESCRIPTION
      Reads the current KeePassConfiguration and displays values for DBDefaultpathPath and KPProgramfolder for the PowerShell KeePass Module.
      The KeePassConfiguration.xml is located in the PSKeePass module root folder.
      
  #>
  #Check if there already is a KeePassConfiguration.xml and write out the configuration
  if (Test-Path -Path $PSScriptRoot\KeePassConfiguration.xml)
  { 

    [xml]$XML = (Get-Content $PSScriptRoot\KeePassConfiguration.xml)
  
    $output = '' | Select-Object DBDefaultpathPath,KPProgramFolder 
    $Output.DBDefaultpathPath = $xml.Settings.KeePassSettings.DBDefaultpathPath
    $Output.KPProgramFolder = $xml.Settings.KeePassSettings.KPProgramFolder
    $output

  }

  else {
    Write-Output 'No KeePass Configuration has been created. You can create one with Set-KeePassConfiguration'
  }

}

##New Code
#load KeePassLib Sdk
function Get-KpLib
{
    <#
        .SYNOPSIS 
            Used to Load the KeePassLib DLL
        .DESCRIPTION
            Used to Load the KeePassLib DLL. Currently the pass is hardcoded-
            but will be updated to be dynamic.
            
            Uses Version 2.3.
            Uses Reflection to load assembly.
        .EXAMPLE
            PS> Get-KpLib
            
            This Exmple Loads the KeePassLib Assembly from the default location.
        .EXAMPLE
            PS> Get-KpLib -KpLib "c:\path\to\KeePassLib.dll"
            
            This Exmple Loads the KeePassLib Assembly from the specified location.
        .PARAMETER KpLib
            This is the path to the KeePassLib Assembly.
    #>
    [CmdletBinding()]
    [OutputType('System.Reflection.Assembly')]
    param
    (
        [Parameter(Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $KpLib
    )
    begin
    {
        if(!$KpLib)
        {
            #$cwd = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
            $KpLib = Resolve-Path -Path "$PSScriptRoot\..\..\Installers\KeePassLib.dll"
            Write-Verbose "Importing KeePassLib from:  $KpLib"
        }
    }
    process
    {
        try
        {
            Write-Verbose "Importing KeePassLib.dll"
            [Reflection.Assembly]::LoadFile($KpLib) > $null
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
        }
        finally
        {
            Write-Verbose "Imported KeePassLib.dll"
        }
    } 
}

#Create a KeePass Credential Object
function Get-KpCred
{
	<#
        .SYNOPSIS
            This function Creates a Keepass Credential Object to be passed to the keepass module.
        .DESCRIPTION
            This function Creates a Keepass Credential Object to be passed to the keepass module. This will be used to to validate passed 
            keepass database credentials and then open said database in a specific way based on passed credentials
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "\\mypath\database.kdbx" -KpKeyPath "\\mypath\database.key"
        
            This Example will create a keepass credential object to be used when opening a keepass database, using the database file and a keepass kee file.
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "\\mypath\database.kdbx" -KpKeyPath "\\mypath\database.key" -KpMasterKey "MyMasterKeyPassword"
        
            This Example will create a keepass credential object to be used when opening a keepass database, using the database file, a keepass kee file, and a masterkey password.
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "\\mypath\database.kdbx" -KpMasterKey "MyMasterKeyPassword"
        
            This Example will create a keepass credential object to be used when opening a keepass database, using the database file and a masterkey password.
        .PARAMETER DatabaseFile
            The path to your Keepass Database File (.kdbx)
        .PARAMETER KeyFile
            The path to your Keepass Encryption Key File (.key)
        .PARAMETER MasterKey
            The Master Key Password to your Keepass Database.
        .INPUTS
            String. All Inputs are passed as a string.
        .OUTPUTS
            System.Management.Automation.PSCustomObject
	#>
    [CmdletBinding(DefaultParameterSetName='Key')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Master')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})] 
        [string]$DatabaseFile,

        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Key')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})] 
        [string]$KeyFile,

        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='Master')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName='KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [string]$MasterKey
    )
    process
    { 
        try
        {
            $output = [Ordered]@{
                'DatabaseFile' = $DatabaseFile
                'KeyFile' = $KeyFile
                'MasterKey' = $MasterKey
                'AuthenticationType' = $PSCmdlet.ParameterSetName
            }
        }
        catch [Exception]
        {
            Throw $_.Exception.Message
        }
        finally
        {
            [PSCustomObject]$output
        }
    }
}

#Open KeePass DB Connection
function Get-KpConn
{
    <#
        .SYNOPSIS
            This Function Creates a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Creates a Connection to a KeePass Database. It Uses a KpCred Object-
            to determine the authentication method. It then connectes to the database and returns-
            an open KeePassLib.PwDatabase object.
            
            Currently this funciton supports these methods of authentication:
                KeyFile
                Master Password
                Master Password and KeyFile
            
            Future Versions will support Windows User Authentication Types.
        .EXAMPLE
            PS> Get-KpConn -KpCred $Creds
            
            This Example will return an KeePass Database Connection using a pre-defined KeePass Credential Object.
        .EXAMPLE
            PS> Get-KpCred -KpDBPath "c:\path\to\database.kdbx" -KpKeyPath "c:\path\to\keyfile.key" -KpMasterKey "masterpassword" | Get-KpConn
            
            This Example will return an KeePass Database Connection using the Credential object passed from pipe.
        .PARAMETER KpCred
            This is the KeePass Credential Object, that is used to open a connection to the KeePass DB.
            
            See Get-KpCred in order to generate this credential object.
    #>
    [CmdletBinding()]
    [OutputType('KeePassLib.PwDatabase')]
    param
    (
        [Parameter(Position=0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $KpCred
    )
    process
    {
        #Create IOConnectionInfo to KPDB using KPLib
        try
        {
            $IOConn = New-Object KeePassLib.Serialization.IOConnectionInfo
            $IOConn.Path = $KpCred.DatabaseFile
            $CompKey = New-Object KeePassLib.Keys.CompositeKey  
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
            Throw $_.Exception
        }
        
        #Determine AuthenticationType and Create KPLib CompositeKey
        try
        {
            if ($KpCred.AuthenticationType -eq "Key")
            {
                $CompKey.AddUserKey((New-Object KeePassLib.Keys.KcpKeyFile($KpCred.KeyFile)))
            }
            elseif ($KpCred.AuthenicationType -eq "KeyAndMaster")
            {
                $CompKey.AddUserKey((New-Object KeePassLib.Keys.KcpKeyFile($KpCred.KeyFile)))
                $CompKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($KpCred.MasterKey)))
            }
            elseif ($KpCred.AuthenticationType -eq "Master") 
            {
                $CompKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($KpCred.MasterKey)))
            }
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
            Throw $_.Exception
        }
        
        #Open KPDB Connection
        try
        {
            $DB = New-Object KeePassLib.PwDatabase
            $DB.Open($IOConn,$CompKey,$null)    
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
            Throw $_.Exception   
        }
        $DB
    }
}

#Close KeePass DB connection
function Remove-KpConn
{
    <#
        .SYNOPSIS
            This Function Removes a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Removes a Connection to a KeePass Database.
        .EXAMPLE
            PS> Remove-KpConn -Connection $DB
            
            This Example will Remove/Close a KeePass Database Connection using a pre-defined KeePass DB connection.
        .PARAMETER Connection
            This is the KeePass Connection to be Closed
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position=0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $Connection
    )
    process
    { 
        try
        {
            $Connection.Close()
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
        }
    }
}

#Fetch a KeePass entry
function Get-KpEntry
{
    <#
        .SYNOPSIS
            This function will lookup and Return KeePass one or more KeePass Entries.
        .DESCRIPTION
            This function will lookup Return KeePass Entry(ies). It supports basic lookup filtering.
        .EXAMPLE
            PS> Get-KpEntry -KpDB $DB -UserName "MyUser"
            
            This Example will return all entries that have the UserName "MyUser"
        .EXAMPLE
            PS> Get-KpEntry -KpDB $DB -KpGroup $KpGroup
            
            This Example will return all entries that are in the specified group.
        .EXAMPLE
            PS> Get-KpEntry -KpDB $DB -UserName "AUserName"
            
            This Example will return all entries have the UserName "AUserName"
        .PARAMETER Connection 
            This is the Open KeePass Database Connection
            
            See Get-Kpconnection to Create the conneciton Object.
        .PARAMETER KpGroup
            This is the KeePass Group Object in which to search for entries.
        .PARAMETER Title
            This is a Title of one or more KeePass Entries.
        .PARAMETER UserName
            This is the UserName of one or more KeePass Entries.

            This is the Password of one ore more KeePass Entries.
    #>
    [CmdletBinding(DefaultParameterSetName="")]
    [OutputType('KeePassLib.PwEntry')]
    param
    (
        [Parameter(Position=0,Mandatory,ParameterSetName="Group")]
        [Parameter(Position=0,Mandatory,ParameterSetName="Title")]
        [Parameter(Position=0,Mandatory,ParameterSetName="UserName")]
        [Parameter(Position=0,Mandatory,ParameterSetName="Password")]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $Connection,
                
        [Parameter(Position=1,Mandatory,ParameterSetName="Group")]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KpGroup,
        
        [Parameter(Position=2,Mandatory=$false,ParameterSetName="Group")]
        [Parameter(Position=1,Mandatory,ParameterSetName="Title")]
        [ValidateNotNullOrEmpty()]
        [string] $Title,
        
        [Parameter(Position=3,Mandatory=$false,ParameterSetName="Group")]
        [Parameter(Position=2,Mandatory=$false,ParameterSetName="Title")]
        [Parameter(Position=1,Mandatory,ParameterSetName="UserName")]
        [ValidateNotNullOrEmpty()]
        [string] $UserName
    )
    process
    { 
        #Get Entries and Filter
        $KpItems = $Connection.RootGroup.GetEntries($true)
        
        #This a lame way of filtering.
        if ($Group)
        {
            $KpItems = foreach($_kpItem in $KpItems)
            {
                if($Group.Contains($_kpItem.ParentGroup))
                {
                    $_kpItem   
                }
            }
        }
        if ($Title)
        {
            $KpItems = foreach($_kpItem in $KpItems)
            {
                if($_kpItem.Strings.ReadSafe("Title").ToLower().Equals($Title.ToLower()))
                {
                    $_kpItem   
                }
            }
        }        
        if ($UserName)
        {
             $KpItems = foreach($_kpItem in $KpItems)
             {
                 if($_kpItem.Strings.ReadSafe("UserName").ToLower().Equals($UserName.ToLower()))
                 {
                    $_kpItem   
                 }
             }
        }        
        $KpItems
    }
}

#Add New KeePass Entry
function Add-KpEntry
{
    <#
        .SYNOPSIS
            This Function will add a new entry to a KeePass Database Group.
        .DESCRIPTION
            This Function will add a new entry to a KeePass Database Group.
            
            Currently This function supportes the basic fields for creating a new KeePass Entry.
        .PARAMETER Connection
            This is the Open KeePass Database Connection
            
            See Get-KpConn to Create the conneciton Object.
        .PARAMETER KpGroup
            This is the KeePass GroupObject to add the new Entry to.
        .PARAMETER Title
            This is the Title of the New KeePass Entry.
        .PARAMETER UserName
            This is the UserName of the New KeePass Entry.
        .PARAMETER Password
            This is the Password of the New KeePass Entry.
        .PARAMETER Notes
            This is the Notes of the New KeePass Entry.
        .PARAMETER URL
            This is the URL of the New KeePass Entry.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position=0,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $Connection,
        [Parameter(Position=1,Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KpGroup,
        [Parameter(Position=2,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $Title,
        [Parameter(Position=3,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,
        [Parameter(Position=4,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.Security.ProtectedString] $KpPassword,
        [Parameter(Position=5,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $Notes,
        [Parameter(Position=6,Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $URL
    )
    begin
    {
        try
        {
            $Entry = New-Object KeePassLib.PwEntry($true, $true) -ErrorAction Stop -ErrorVariable ErrorNewPwEntryObject 
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpEntry Cmdlet.'
            if($ErrorNewPwGroupObject)
            { 
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
                Write-Warning -Message "[BEGIN] $($ErrorNewPwEntryObject.ErrorRecord.Message)"
                Throw $_ 
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
    }
    process
    { 
        
        if($Title)
        {
            $SecTitle = New-Object KeePassLib.Security.ProtectedString($Connection.MemoryProtection.ProtectTitle, $Title)
            $Entry.Strings.Set("Title", $SecTitle)    
        }
        
        if($UserName)
        {
            $SecUser = New-Object KeePassLib.Security.ProtectedString($Connection.MemoryProtection.ProtectUserName, $UserName)
            $Entry.Strings.Set("UserName", $SecUser)    
        }
        
        if($KpPassword)
        {            
            $Entry.Strings.Set("Password", $KpPassword)
        }
        else
        {
            #get password based on default pattern
            $KpPassword = Get-KpPass
            $Entry.Strings.Set("Password", $KpPassword)
        }
        
        if($Notes)
        {
            $SecNotes = New-Object KeePassLib.Security.ProtectedString($Connection.MemoryProtection.ProtectNotes, $Notes)
            $Entry.Strings.Set("Notes", $SecNotes)    
        }
        
        if($URL)
        {
            $SecURL = New-Object KeePassLib.Security.ProtectedString($Connection.MemoryProtection.ProtectUrl, $URL)
            $Entry.Strings.Set("URL", $SecURL)
        }
        
        #Add to Group
        $KpGroup.AddEntry($Entry,$true)
    }
    end{ $Connection.Save($null) }
}

#Gets a KeePass Group object
function Get-KpGroup
{
    <#
        .SYNOPSIS
            Gets a KeePass Group Object.
        .DESCRIPTION
            Gets a KeePass Group Object. Type: KeePassLib.PwGroup
        .EXAMPLE
            PS> Get-KpGroup -Connection $Conn -FullPath 'full/KPDatabase/pathtoGroup'
            
            This Example will return a KeePassLib.PwGroup array Object with the full group path specified.
        .EXAMPLE
            PS> Get-KpGroup -Connection $Conn -GroupName 'Test Group'
            
            This Example will return a KeePassLib.PwGroup array Object with the groups that have the specified name.
        .PARAMETER Connection
            Specify the Open KeePass Database Connection
            
            See Get-Kpconnection to Create the conneciton Object.
        .PARAMETER FullPath
            Specify the FullPath of a Group or Groups in a KPDB
        .PARAMETER GroupName
            Specify the GroupName of a Group or Groups in a KPDB.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Full')]
    [OutputType('KeePassLib.PwGroup')]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ParameterSetName = 'Full'
        )]
        [Parameter(
            Position = 0,
            Mandatory,
            ParameterSetName = 'Partial'
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $Connection,
        [Parameter(
            Position = 1,
            Mandatory,
            ParameterSetName = 'Full',
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()] 
        [string[]] $FullPath,
        [Parameter(
            Position = 1,
            Mandatory,
            ParameterSetName = 'Partial',
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [string[]] $GroupName
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup[]] $KpOutGroups = $null
            [KeePassLib.PwGroup] $KpGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject
            $KpGroups = $Connection.RootGroup.GetFlatGroupList() 
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Get-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            { 
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message "[BEGIN] $($ErrorNewPwGroupObject.ErrorRecord.Message)"
                Throw $_ 
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
        
    }
    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Full')
        {
            foreach($Path in $FullPath)
            {
                foreach($_kpGroup in $KpGroups)
                {
                    if($_kpGroup.GetFullPath("/", $false).Equals($Path))
                    {
                        $KpOutGroups += $_kpGroup
                    }
                }   
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Partial')
        {
            foreach($Name in $GroupName )
            {
                foreach($_kpGroup in $KpGroups)
                {
                    if($_kpGroup.Name.Equals($Name))
                    {
                        $KpOutGroups += $_kpGroup
                    }
                }
            }
        } 
    }
    end{ $KpOutGroups }
}

#Create a New KeePass Group
function Add-KpGroup
{
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KpGroup -Connection $Conn -GroupName 'NewGroupName' -ParentGroupPath $KpGroup
            
            This Example Create a New Group with the specified name in the specified ParentGroup.
        .PARAMETER Connection
            This is the Open KeePass Database Connection
            
            See Get-KpConn to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER ParentGroup
            Sepcify the ParentGroup(s) for the new Group(s).
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $Connection,
        [Parameter(
            Position = 1,
            Mandatory
        )]
        [ValidateNotNullorEmpty()]
        [string[]] $GroupName,
        [Parameter(
            Position = 2,
            Mandatory
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $ParentGroup
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup] $KpGroup = New-Object KeePassLib.PwGroup -ErrorAction Stop -ErrorVariable ErrorNewPwGroupObject    
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured in the Add-KpGroup Cmdlet.'
            if($ErrorNewPwGroupObject)
            { 
                Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
                Write-Warning -Message "[BEGIN] $($ErrorNewPwGroupObject.ErrorRecord.Message)"
                Throw $_ 
            }
            else
            {
                Write-Warning -Message '[BEGIN] An unhandled exception occured.'
                Write-Warning -Message '[BEGIN] Verify your KeePass Database Connection is Open.'
                Throw $_
            }
        }
    }
    process
    {   
        foreach($Group in $ParentGroup)
        {
            foreach($Name in $GroupName)
            {
                $KpGroup.Name = $GroupName
                $Group.AddGroup($KpGroup, $true)
            }
        }  
    }
    end{ $Connection.Save($null) }
}

#Generates a Password Using the KeePass Password Generator
function Get-KpPass
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
            PS> Get-KpPass
            
            This Example will generate a Password using the Default KeePass Password Profile.
            Which I believe is -UpperCase -LowerCase -Digites -Length 20
        .EXAMPLE
            PS> Get-KpPass -UpperCase -LowerCase -Digits -Length 20
            
            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9
        .EXAMPLE
            PS> Get-KpPass -UpperCase -LowerCase -Digits -SpecialCharacters -ExcludeCharacters '"' -Length 20
            
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
    #>
    [CmdletBinding()]
    [OutputType('KeePassLib.Security.ProtectedString')]
    param
    (
        [Parameter(Position=0)]
        [ValidateNotNull()]
        [Switch] $UpperCase,
        [Parameter(Position=1)]
        [ValidateNotNull()]
        [Switch] $LowerCase,
        [Parameter(Position=2)]
        [ValidateNotNull()]
        [Switch] $Digits,
        [Parameter(Position=3)]
        [ValidateNotNull()]
        [Switch] $SpecialCharacters,
        # [Parameter(Position=4)]
        # [ValidateNotNull()]
        # [Switch] $HighANSICharacters,
        [Parameter(Position=5)]
        [ValidateNotNull()]
        [Switch] $Minus,
        [Parameter(Position=6)]
        [ValidateNotNull()]
        [Switch] $UnderScore,
        [Parameter(Position=7)]
        [ValidateNotNull()]
        [Switch] $Space,
        [Parameter(Position=8)]
        [ValidateNotNull()]
        [Switch] $Brackets,
        [Parameter(Position=9)]
        [ValidateNotNull()]
        [Switch] $ExcludeLookALike,
        [Parameter(Position=10)]
        [ValidateNotNull()]
        [Switch] $NoRepeatingCharacters,
        [Parameter(Position=11)]
        [ValidateNotNullOrEmpty()]
        [string] $ExcludeCharacters,
        [Parameter(Position=12)]
        [ValidateNotNullOrEmpty()]
        [int] $Length
    )
    process
    {
        #Create New Password Profile.
        $PassProfile = New-Object KeePassLib.Cryptography.PasswordGenerator.PwProfile
        
        if($PSBoundParameters.Count -gt 0)
        {
            $PassProfile.CharSet = New-Object KeePassLib.Cryptography.PasswordGenerator.PwCharSet  
            #Build Profile With Options.
            if($UpperCase){ $PassProfile.CharSet.Add('ABCDEFGHIJKLMNOPQRSTUVWXYZ') }
            if($LowerCase){ $PassProfile.CharSet.Add('abcdefghijklmnopqrstuvwxyz') }
            if($Digits){ $PassProfile.CharSet.Add('0123456789') }
            if($SpecialCharacters){ $PassProfile.CharSet.Add('!"#$%&''*+,./:;=?@\^`|~') }
            #if($HighANSICharacters){ $PassProfile.CharSet.Add('¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ') }
            if($Minus){ $PassProfile.CharSet.Add('-') }
            if($UnderScore){ $PassProfile.CharSet.Add('_') }
            if($Space){ $PassProfile.CharSet.Add(' ') }
            if($Brackets){ $PassProfile.CharSet.Add('[]{}()<>') }
            if($ExcludeLookALike){ $PassProfile.ExcludeLookAlike = $true }
            if($NoRepeatingCharacters){ $PassProfile.NoRepeatingCharacters = $true }
            if($ExcludeCharacters){ $PassProfile.ExcludeCharacters = $ExcludeCharacters }
            if($Length){ $PassProfile.Length = $Length }  
        }
        #Create Pass Generator Profile Pool.
        $GenPassPool = New-Object KeePassLib.Cryptography.PasswordGenerator.CustomPwGeneratorPool
        #Create Out Parameter aka [rel] param.
        [KeePassLib.Security.ProtectedString]$PSOut = New-Object KeePassLib.Security.ProtectedString
        #Generate Password.
        [KeePassLib.Cryptography.PasswordGenerator.PwGenerator]::Generate([ref] $PSOut, $PassProfile, $null, $GenPassPool) > $null
        # $PSOut.GetType();
    }
    end{ $PSOut }
}

#reads string from KeePassLib.Security.ProtectedString
function ConvertFrom-KpProtectedString
{
    <#
        .SYNOPSIS
            This Function will Convert a KeePass ProtectedString to Plain Text.
        .DESCRIPTION
            This Function will Convert a KeePassLib.Security.ProtectedString to Plain Text.
            
            This Would Primarily be used for Reading Title,UserName,Password,Notes, and URL ProtectedString Values.
        .EXAMPLE
            PS>Get-KpPass -UpperCase -LowerCase -Digits -SpecialCharacters -Length 21 | ConvertFrom-KpProtectedString
            
            This Example will created a password using the specified options and convert the resulting password to a string.
        .PARAMETER ProtectedString
            This is the KeePassLib.Security.ProtectedString to be converted to plain text
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Position=0,Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.Security.ProtectedString] $ProtectedString
    )
    process
    {
        $ProtectedString.ReadString()
    }
}

#creates a powershell object from one or more keepass entries.
function ConvertTo-KpPsObject
{
    <#
        .SYNOPSIS 
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.
        .DESCRIPTION
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.
            
            It will get the Protected Strings from the database like, Title,UserName,Password,URL,Notes.
           
            It currently returns Most frequently used data about an entry and excludes extensive metadata such as-
            Foreground Color, Icon, ect.
        .EXAMPLE
            PS> Convert-ToKpPsObject -KpEntry $Entry
            
            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .EXAMPLE
            PS> Get-KpEntry -Connection $DB -UserName "AUserName" | Convert-ToKpPsObject
            
            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .PARAMETER Entry
            This is the one or more KeePass Entries to be converted.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Position=0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $Entry
    )
    begin{ $KpPSOutObject = @() }
    process
    {
        
        foreach ($_kpItem in $Entry)
        {
            $KpPsObject = New-Object -TypeName PSObject
            $KpPsObject | Add-Member -Name 'CreationTime' -MemberType NoteProperty -Value $_kpItem.CreationTime
            $KpPsObject | Add-Member -Name 'Expires' -MemberType NoteProperty -Value $_kpItem.Expires
            $KpPsObject | Add-Member -Name 'ExpireTime' -MemberType NoteProperty -Value $_kpItem.ExpiryTime
            $KpPsObject | Add-Member -Name 'LastAccessTime' -MemberType NoteProperty -Value $_kpItem.LastAccessTime
            $KpPsObject | Add-Member -Name 'LastModificationTime' -MemberType NoteProperty -Value $_kpItem.LastModificationTime
            $KpPsObject | Add-Member -Name 'LocationChanged' -MemberType NoteProperty -Value $_kpItem.LocationChanged
            $KpPsObject | Add-Member -Name 'Tags' -MemberType NoteProperty -Value $_kpItem.Tags
            $KpPsObject | Add-Member -Name 'Touched' -MemberType NoteProperty -Value $_kpItem.Touched
            $KpPsObject | Add-Member -Name 'UsageCount' -MemberType NoteProperty -Value $_kpItem.UsageCount
            $KpPsObject | Add-Member -Name 'ParentGroup' -MemberType NoteProperty -Value $_kpItem.ParentGroup.Name
            $KpPsObject | Add-Member -Name 'FullPath' -MemberType NoteProperty -Value $_kpItem.ParentGroup.GetFullPath("/", $false)
            $KpPsObject | Add-Member -Name 'Title' -MemberType NoteProperty -Value $_kpItem.Strings.ReadSafe("Title")
            $KpPsObject | Add-Member -Name 'UserName' -MemberType NoteProperty -Value $_kpItem.Strings.ReadSafe("UserName")
            $KpPsObject | Add-Member -Name 'Password' -MemberType NoteProperty -Value $_kpItem.Strings.ReadSafe("Password")
            $KpPsObject | Add-Member -Name 'URL' -MemberType NoteProperty -Value $_kpItem.Strings.ReadSafe("URL")
            $KpPsObject | Add-Member -Name 'Notes' -MemberType NoteProperty -Value $_kpItem.Strings.ReadSafe("Notes")
            $KpPSOutObject += $KpPsObject  
        }       
    }
    end{ $KpPSOutObject }
}