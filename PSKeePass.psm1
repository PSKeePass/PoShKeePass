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
