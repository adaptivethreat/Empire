function Invoke-HostRecon{

    <#

    .SYNOPSIS

    This function runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.

    HostRecon Function: Invoke-HostRecon
    Author: Beau Bullock (@dafthack) with credit to Joff Thyer (@joff_thyer) for the portscan module.
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION

    This function runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.

    .PARAMETER Portscan

    If this flag is added an outbound portscan will be initiated from the target system to allports.exposed. The top 50 ports as specified by the Nmap project will be scanned. This is useful in determining any egress filtering in use.
    
    .PARAMETER TopPorts

    This flag specifies the number of "top ports" to be scanned outbound from the system. Valid entries are 1-128. Default is 50.

    .Example

    C:\PS> Invoke-HostRecon

    Description
    -----------
    This command will run a number of checks on the local system including the retrieval of local system information (netstat, common security products, scheduled tasks, local admins group, LAPS, etc), and domain information (Domain Admins group, DC's, password policy).

    .Example

    C:\PS> Invoke-HostRecon -Portscan -TopPorts 128

    Description
    -----------
    This command will run a number of checks on the local system including the retrieval of local system information (netstat, common security products, scheduled tasks, local admins group, LAPS, etc), and domain information (Domain Admins group, DC's, password policy). Additionally, it will perform an outbound portscan on the top 128 ports to allports.exposed to assist in determining any ports that might be allowed outbound for C2 communications.

    #>

    Param(
        
        [Parameter(Position = 0, Mandatory = $false)]
        [switch]
        $Portscan,

        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $TopPorts = "50",

        [Parameter(Position = 2, Mandatory = $false)]
        [switch]
        $DisableDomainChecks = $false,

        [ValidateRange(1,65535)][String[]]$Portlist = ""

    )

    #Hostname

    Write-Output "[*] Hostname"
    $Computer = $env:COMPUTERNAME
    $Computer
    Write-Output "`n"

    #IP Information

    Write-Output "[*] IP Address Info"
    $ipinfo = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'| Select-Object IPAddress,Description | Format-Table -Wrap | Out-String
    $ipinfo
    Write-Output "`n"

    #Current user and domain

    Write-Output "[*] Current Domain and Username"

    $currentuser = $env:USERNAME
    Write-Output "Domain = $env:USERDOMAIN"
    Write-Output "Current User = $env:USERNAME"
    Write-Output "`n"

    #All local users

    Write-Output "[*] Local Users of this system"
    $locals = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Select-Object Name 
    $locals
    Write-Output "`n"

    #Local Admins group

    Write-Output "[*] Local Admins of this system"
    $Admins = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent } | Select-Object Caption,SID | format-table -Wrap | Out-String
    $Admins
    Write-Output "`n"

    #Netstat Information
    #Some code here borrowed from: http://techibee.com/powershell/query-list-of-listening-ports-in-windows-using-powershell/2344
        Write-Output "[*] Active Network Connections"
        $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
        $Connections = $TCPProperties.GetActiveTcpConnections()            
        $objarray = @()
        foreach($Connection in $Connections) {            
            if($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
            $OutputObj = New-Object -TypeName PSobject            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $Connection.LocalEndPoint.Address            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalPort" -Value $Connection.LocalEndPoint.Port            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "RemoteAddress" -Value $Connection.RemoteEndPoint.Address            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "RemotePort" -Value $Connection.RemoteEndPoint.Port            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "State" -Value $Connection.State            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
            $objarray += $OutputObj
            }
            $activeconnections = $objarray | Format-Table -Wrap | Out-String
            $activeconnections

       Write-Output "[*] Active TCP Listeners"            
        $ListenConnections = $TCPProperties.GetActiveTcpListeners()            
        $objarraylisten = @()
            foreach($Connection in $ListenConnections) {            
            if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
            $OutputObjListen = New-Object -TypeName PSobject            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
            $objarraylisten += $OutputObjListen }
            $listeners = $objarraylisten | Format-Table -Wrap | Out-String
            $listeners
        
    Write-Output "`n"

    #DNS Cache Information

    Write-Output "[*] DNS Cache"

    try{
    $dnscache = Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" -ErrorAction stop | Select-Object Entry,Name,Data | Format-Table -Wrap | Out-String
    $dnscache
    }
    catch
        {
        Write-Output "There was an error retrieving the DNS cache."
        }
    Write-Output "`n"

    #Shares

    Write-Output "[*] Share listing"
    $shares = @()
    $shares = Get-WmiObject -Class Win32_Share | Format-Table -Wrap | Out-String
    $shares
    Write-Output "`n"

    #Scheduled Tasks

    Write-Output "[*] List of scheduled tasks"
    $schedule = new-object -com("Schedule.Service")
    $schedule.connect() 
    $tasks = $schedule.getfolder("\").gettasks(0) | Select-Object Name | Format-Table -Wrap | Out-String
    If ($tasks.count -eq 0)
        {
        Write-Output "[*] Task scheduler appears to be empty"
        }
    If ($tasks.count -ne 0)
        {
        $tasks
        }
    Write-Output "`n"

    #Proxy information

    Write-Output "[*] Proxy Info"
    $proxyenabled = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyEnable
    $proxyserver = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer

    If ($proxyenabled -eq 1)
        {
            Write-Output "A system proxy appears to be enabled."
            Write-Output "System proxy located at: $proxyserver"
        }
    Elseif($proxyenabled -eq 0)
        {
            Write-Output "There does not appear to be a system proxy enabled."
        }
    Write-Output "`n"

    #Getting AntiVirus Information


    Write-Output "[*] Checking if AV is installed"

    $AV = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" 

    If ($AV -ne "")
        {
            Write-Output "The following AntiVirus product appears to be installed:" $AV.displayName
        }
    If ($AV -eq "")
        {
            Write-Output "No AV detected."
        }
    Write-Output "`n"

    #Getting Local Firewall Status

    Write-Output "[*] Checking local firewall status."
    $HKLM = 2147483650
    $reg = get-wmiobject -list -namespace root\default -computer $computer | where-object { $_.name -eq "StdRegProv" }
    $firewallEnabled = $reg.GetDwordValue($HKLM, "System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile","EnableFirewall")
    $fwenabled = [bool]($firewallEnabled.uValue)

    If($fwenabled -eq $true)
        {
            Write-Output "The local firewall appears to be enabled."
        }
    If($fwenabled -ne $true)
        {
            Write-Output "The local firewall appears to be disabled."
        }
    Write-Output "`n"

    #Checking for Local Admin Password Solution (LAPS)

    Write-Output "[*] Checking for Local Admin Password Solution (LAPS)"
    try
        {
        $lapsfile = Get-ChildItem "$env:ProgramFiles\LAPS\CSE\Admpwd.dll" -ErrorAction Stop
        if ($lapsfile)
            {
            Write-Output "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use."
            }
        }
    catch
        {
        Write-Output "The LAPS DLL was not found."
        }
    Write-Output "`n"

    #Process Information

    Write-Output "[*] Running Processes"

    $processes = Get-Process | Select-Object ProcessName,Id,Description,Path 
    $processout = $processes | Format-Table -Wrap | Out-String
    $processout
    Write-Output "`n"

    #Checking for common security products

    Write-Output "[*] Checking for Sysinternals Sysmon"
    try
        {
        $sysmondrv = Get-ChildItem "$env:SystemRoot\sysmondrv.sys" -ErrorAction Stop
        if ($sysmondrv)
            {
            Write-Output "The Sysmon driver $($sysmondrv.VersionInfo.FileVersion) (sysmondrv.sys) was found. System activity may be monitored."
            }
        }
    catch
        {
        Write-Output "The Sysmon driver was not found."
        }
    Write-Output "`n"

    Write-Output "[*] Checking for common security product processes"
    $processnames = $processes | Select-Object ProcessName
    Foreach ($ps in $processnames)
            {
            #AV
            if ($ps.ProcessName -like "*mcshield*")
                {
                Write-Output ("Possible McAfee AV process " + $ps.ProcessName + " is running.")
                }
            if (($ps.ProcessName -like "*windefend*") -or ($ps.ProcessName -like "*MSASCui*") -or ($ps.ProcessName -like "*msmpeng*") -or ($ps.ProcessName -like "*msmpsvc*"))
                {
                Write-Output ("Possible Windows Defender AV process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*WRSA*")
                {
                Write-Output ("Possible WebRoot AV process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*savservice*")
                {
                Write-Output ("Possible Sophos AV process " + $ps.ProcessName + " is running.")
                }
            if (($ps.ProcessName -like "*TMCCSF*") -or ($ps.ProcessName -like "*TmListen*") -or ($ps.ProcessName -like "*NTRtScan*"))
                {
                Write-Output ("Possible Trend Micro AV process " + $ps.ProcessName + " is running.")
                }
            if (($ps.ProcessName -like "*symantec antivirus*") -or ($ps.ProcessName -like "*SymCorpUI*") -or ($ps.ProcessName -like "*ccSvcHst*") -or ($ps.ProcessName -like "*SMC*")  -or ($ps.ProcessName -like "*Rtvscan*"))
                {
                Write-Output ("Possible Symantec AV process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*mbae*")
                {
                Write-Output ("Possible MalwareBytes Anti-Exploit process " + $ps.ProcessName + " is running.")
                }
            #if ($ps.ProcessName -like "*mbam*")
               # {
               # Write-Output ("Possible MalwareBytes Anti-Malware process " + $ps.ProcessName + " is running.")
               # }
            #AppWhitelisting
            if ($ps.ProcessName -like "*Parity*")
                {
                Write-Output ("Possible Bit9 application whitelisting process " + $ps.ProcessName + " is running.")
                }
            #Behavioral Analysis
            if ($ps.ProcessName -like "*cb*")
                {
                Write-Output ("Possible Carbon Black behavioral analysis process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*bds-vision*")
                {
                Write-Output ("Possible BDS Vision behavioral analysis process " + $ps.ProcessName + " is running.")
                } 
            if ($ps.ProcessName -like "*Triumfant*")
                {
                Write-Output ("Possible Triumfant behavioral analysis process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "CSFalcon")
                {
                Write-Output ("Possible CrowdStrike Falcon EDR process " + $ps.ProcessName + " is running.")
                }
            #Intrusion Detection
            if ($ps.ProcessName -like "*ossec*")
                {
                Write-Output ("Possible OSSEC intrusion detection process " + $ps.ProcessName + " is running.")
                } 
            #Firewall
            if ($ps.ProcessName -like "*TmPfw*")
                {
                Write-Output ("Possible Trend Micro firewall process " + $ps.ProcessName + " is running.")
                } 
            #DLP
            if (($ps.ProcessName -like "dgagent") -or ($ps.ProcessName -like "DgService") -or ($ps.ProcessName -like "DgScan"))
                {
                Write-Output ("Possible Verdasys Digital Guardian DLP process " + $ps.ProcessName + " is running.")
                }   
            if ($ps.ProcessName -like "kvoop")
                {
                Write-Output ("Possible Unknown DLP process " + $ps.ProcessName + " is running.")
                }                       
            }
    Write-Output "`n"

    if ($DisableDomainChecks -eq $false)
    {
    #Domain Password Policy

    $domain = "$env:USERDOMAIN"
    Write-Output "[*] Domain Password Policy"
            Try 
            {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                $CurrentDomain = [ADSI]"WinNT://$env:USERDOMAIN"
                $Name = @{Name="DomainName";Expression={$_.Name}}
	            $MinPassLen = @{Name="Minimum Password Length";Expression={$_.MinPasswordLength}}
                $MinPassAge = @{Name="Minimum Password Age (Days)";Expression={$_.MinPasswordAge.value/86400}}
	            $MaxPassAge = @{Name="Maximum Password Age (Days)";Expression={$_.MaxPasswordAge.value/86400}}
	            $PassHistory = @{Name="Enforce Password History (Passwords remembered)";Expression={$_.PasswordHistoryLength}}
	            $AcctLockoutThreshold = @{Name="Account Lockout Threshold";Expression={$_.MaxBadPasswordsAllowed}}
	            $AcctLockoutDuration =  @{Name="Account Lockout Duration (Minutes)";Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
	            $ResetAcctLockoutCounter = @{Name="Observation Window";Expression={$_.LockoutObservationInterval.value/60}}
	            $CurrentDomain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter | format-list | Out-String

            }
            catch 
            {
                Write-Output "Error connecting to the domain while retrieving password policy."    

            }
    Write-Output "`n"

    #Domain Controllers

    Write-Output "[*] Domain Controllers"
            Try 
            {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                $DCS = $DomainObject.DomainControllers
                foreach ($dc in $DCS)
                {
                    $dc.Name
                }
            
            }
            catch 
            {
                Write-Output "Error connecting to the domain while retrieving listing of Domain Controllers."    

            }
       Write-Output "`n"
   
    #Domain Admins

    Write-Output "[*] Domain Admins"
            Try 
            {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            
                $DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
                $Members = @($DAgroup.psbase.invoke("Members"))
                [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
                $MemberNames
            }
            catch 
            {
                Write-Output "Error connecting to the domain while retrieving Domain Admins group members."    

            }
       Write-Output "`n"
    }
    If($Portscan)
    {
    if ($Portlist -ne "")
    {
    TCP-PortScan -Portlist $Portlist
    }
    else
    {
    TCP-PortScan -TopPorts $TopPorts
    }
    }

}


function TCP-PortScan {
<#
.SYNOPSIS

Perform a full TCP connection scan to the destination hostname, or to 'allports.exposed' if that destination is not supplied.

Author: Joff Thyer, April 2014

.DESCRIPTION

TCP-Portscan is designed to perform a full TCP connection scan to the destination
hostname using either a port range of top X number of popular TCP ports.  The top
popular port list is derived from NMAP's services using the frequrency measurements
that appear in this file.  If the top X number of popular ports is not the desired
behavior, you can specify a minimum and maximum port number within which a range of
ports will be scanned.  By default, a random delay between 50 and 200 milliseconds
is added in order to assist in avoiding detection.  Also by default, if the hostname
is not specified then 'allports.exposed' will be used as a default.   The 'allports.exposed'
site responds to all TCP ports will the text of 'woot woot' if an HTTP request is sent,
but more to the point, all ports are considered open.

.PARAMETER Hostname

If provided, the hostname will be looked up and the resulting IP address used
as the IP address to be scanned.  If not provided, then the default hostname
of 'allports.exposed' will be used.

.PARAMETER MinPort

Specify the minimum port number in a range of ports to be scanned.

.PARAMETER MaxPort

Specify the maximum port number in a range of ports to be scanned.

.PARAMETER TopPorts

Specify the number of popular ports which you would like to be scanned.  Up to
128 ports may be specified.

.PARAMETER Timeout

Specify the TCP connection timeout in the range of 10 - 10000 milliseconds.

.PARAMETER NoRandomDelay

Disable the random delay between connection attempts.

#>

    param(  [String]$Hostname = 'allports.exposed',
            [ValidateRange(1,65535)][Int]$MinPort = 1,
            [ValidateRange(1,65535)][Int]$MaxPort = 1,
            [ValidateRange(1,128)][Int]$TopPorts = 50,
            [ValidateRange(10,10000)][Int]$Timeout = 400,
            [ValidateRange(1,65535)][String[]]$Portlist = "",
            [switch]$NoRandomDelay = $false )

    $resolved = [System.Net.Dns]::GetHostByName($Hostname)
    $ip = $resolved.AddressList[0].IPAddressToString

    # TopN port collection derived from NMAP project
    $tcp_top128 =  80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, `
135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, `
1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, `
8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, `
5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, `
2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, `
144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, `
3986, 13, 1029, 9, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, `
119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, `
6004, 1801, 19, 8031, 1041, 255, 3703, 17, 808, 3689, 1031, 1071, `
5901, 9102, 9000, 2105, 636, 1038, 2601, 7000

    $report = @()
    if ($MaxPort -gt 1 -and $MinPort -lt $MaxPort) {
        $ports = $MinPort..$MaxPort
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), port range $MinPort -> $MaxPort : "
    }
    elseif ($MaxPort -lt $MinPort) {
        Throw "Are you out of your mind?  Port range cannot go negative."
    }
    elseif($Portlist -ne ""){
    $ports = $Portlist
    Write-Host -NoNewline "[*] Scanning $Hostname ($ip), using the portlist provided."
    }
    else {
        $PortDiff = $TopPorts - 1
        $ports = $tcp_top128[0..$PortDiff]
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), top $TopPorts popular ports : "
    }
    
    $total = 0
    $tcp_count = 0
    foreach ($port in Get-Random -input $ports -count $ports.Count) {
        if (![Math]::Floor($total % ($ports.Count / 10))) {
            Write-Host -NoNewline "."
        }
        $total += 1
        $temp = "" | Select Address, Port, Proto, Status, Banner
        $temp.Proto = "tcp"
        $temp.Port = $port
        $temp.Address = $ip
        $tcp = new-Object system.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ip,$port,$null,$null)
        $wait = $connect.AsyncWaitHandle.WaitOne($Timeout,$false)
        if (!$wait) {
            $error.clear()
            $tcp.close()
            $temp.Status = "closed"
        }
        else {
            try {
                $tcp.EndConnect($connect)
                $tcp.Close()
                $temp.Status = "open"
                $tcp_count += 1
            }
            catch {
                $temp.Status = "reset"
            }
        }
        $report += $temp

        # add random delay if we want it
        if (!$NoRandomDelay) {
            $sleeptime = Get-Random -Minimum 50 -Maximum 200
            Start-Sleep -Milliseconds $sleeptime
        }
    }
    Write-Host
    $columns = @{l='IP-Address';e={$_.Address}; w=15; a="left"},@{l='Proto';e={$_.Proto};w=5;a="right"},@{l='Port';e={$_.Port}; w=5; a="right"},@{l='Status';e={$_.Status}; w=4; a="right"}
    $report | where {$_.Status -eq "open"} | Sort-Object Port | Format-Table $columns -AutoSize
    Write-Output "[*] $tcp_count out of $total scanned ports are open!"
}
