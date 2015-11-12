function Invoke-WinEnum{

    <#
    .SYNOPSIS
    Collects all revelant information about a host and the current user context.

    .DESCRIPTION
    This script conducts user, system, and network enumeration using the current user context or with a specified user and/or keyword. 

    .PARAMETER UserName
    Specify a user to enumerate. The default is the current user context. 

    .PARAMETER keywords
    Specify a keyword or array of keywords to use in file searches.
    
    .EXAMPLE
    Conduct enumeration with a username and keyword
    
    Invoke-WindowsEnum -User "sandersb"

    .EXAMPLE
    Conduct enumeration with a keyword for file searches. 
    
    Invoke-WindowsEnum -keyword "putty"

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,Position=0)]
        [string]$UserName,
        [Parameter(Mandatory=$False,Position=1)]
        [string[]]$keywords
    )


    Function Get-UserInfo{
        if($UserName){
            "UserName: $UserName`n"
            $DomainUser = $UserName  
        }
        else{
             #If the username was not provided, 
            $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $UserName = $DomainUser.split('\')[-1]
            "UserName: $UserName`n"
            
        }

        "`n-------------------------------------`n"
        "AD Group Memberships"
        "`n-------------------------------------`n"
        #https://social.technet.microsoft.com/Forums/scriptcenter/en-US/c8001c25-edb5-44b2-ad07-37b39285995f/systemdirectoryservicesaccountmanagement-and-powershell?forum=ITCG
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        #Load assembly to User Principal and principalContext .Net classes
        $dsclass = "System.DirectoryServices.AccountManagement"
        $dsclassUP = "$dsclass.userprincipal" -as [type] 
        $iType = "SamAccountName"
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        #Get the current domain 
        $contextTypeDomain = New-object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain,$Domain.Name) 
        #Set the context to the current domain 
        $cName = $Domain.GetDirectoryEntry().distinguishedName
        #Get the distinguishedName for the domain 
        $usr = $dsclassUP::FindByIdentity($contextTypeDomain,$iType,$DomainUser)
        #Grab the user principal object for the domain.
        $usr.GetGroups() | foreach {$_.Name}
        #Enumerate all groups the user is apart of
        
        
        "`n-------------------------------------`n"
        "Password Last changed"
        "`n-------------------------------------`n"

        $($usr.LastPasswordSet) + "`n"
            
        "`n-------------------------------------`n"
        "Last 5 files opened"
        "`n-------------------------------------`n"
            
        $AllOpenedFiles = Get-ChildItem -Path "C:\" -Recurse -Include @("*.txt","*.pdf","*.docx","*.doc","*.xls","*.ppt") -ea SilentlyContinue | Sort-Object {$_.LastAccessTime} 
        $LastOpenedFiles = @()
        $AllOpenedFiles | ForEach-Object {
            $owner = $($_.GetAccessControl()).Owner
            $owner = $owner.split('\')[-1]
            if($owner -eq $UserName){
                $LastOpenedFiles += $_
            }
        }
        if($LastOpenedFiles){
            $LastOpenedFiles | Sort-Object LastAccessTime -Descending | Select-Object FullName, LastAccessTime -First 5 | Format-List | Out-String
        }
        
        "`n-------------------------------------`n"
        "Interesting Files"
        "`n-------------------------------------`n"
        #If the keyword is set, use it in the file search 
        $NewestInterestingFiles = @()
        if($keywords)
        {
            $AllInterestingFiles = Get-ChildItem -Path "C:\" -Recurse -Include $keywords -ea SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} | Sort-Object {$_.LastAccessTime}
            $AllInterestingFiles | ForEach-Object {
                $owner = $_.GetAccessControl().Owner
                $owner = $owner.split('\')[-1]
                if($owner -eq $UserName){
                    $NewestInterestingFiles += $_
                }
            } 
            if($NewestInterestingFiles){
                $NewestInterestingFiles | Sort-Object LastAccessTime -Descending | Select-Object FullName, LastAccessTime | Format-List | Out-String
            }
        }
        else
        {
            $AllInterestingFiles = Get-ChildItem -Path "C:\" -Recurse -Include @("*.txt","*.pdf","*.docx","*.doc","*.xls","*.ppt","*pass*","*cred*") -ErrorAction SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} | Sort-Object {$_.LastAccessTime} 
            $AllInterestingFiles | ForEach-Object {
                $owner = $_.GetAccessControl().Owner
                $owner = $owner.split('\')[-1]
                if($owner -eq $UserName){
                    $NewestInterestingFiles += $_
                }
            }
            if($NewestInterestingFiles)
            {
                $NewestInterestingFiles | Sort-Object LastAccessTime -Descending | Select-Object FullName, LastAccessTime | Format-List | Out-String
            }
        }
        
        "`n-------------------------------------`n"
        "Clipboard Contents"
        "`n-------------------------------------`n"
        #http://www.bgreco.net/powershell/get-clipboard/
        
        $cmd = {
            Add-Type -Assembly PresentationCore
            [Windows.Clipboard]::GetText() -replace "`r", '' -split "`n"  
        }
        if([threading.thread]::CurrentThread.GetApartmentState() -eq 'MTA'){
            & powershell -Sta -Command $cmd
        }
        else{
            $cmd
        }
        "`n"
    }
      
    Function Get-SysInfo{
        "`n-------------------------------------`n"
        "System Information"
        "`n-------------------------------------`n"
        #Grab the Windows Version and arch
        $OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
        $OSArch = (Get-WmiObject -class win32_operatingsystem).OSArchitecture
        "OS: $OSVersion $OSArch`n"
        
        if($OSArch -eq '64-bit')
        {
            $registeredAppsx64 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredAppsx86 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredAppsx64 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize | Out-String
            $registeredAppsx86 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize | Out-String
        }
        else
        {
            $registeredAppsx86 =  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredAppsx86 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize | Out-String
        }

        "`n-------------------------------------`n"
        "Services"
        "`n-------------------------------------`n"

        $AllServices = @()
        Get-WmiObject -class win32_service | ForEach-Object{
            $service = New-Object PSObject -Property @{
                ServiceName = $_.DisplayName
                ServiceStatus = (Get-service | where-object { $_.DisplayName -eq $ServiceName}).status
                ServicePathtoExe = $_.PathName
                StartupType = $_.StartMode
            }
            $AllServices += $service  
        }

        $AllServices | Select ServicePathtoExe, ServiceName | Format-Table -AutoSize | Out-String

        "`n-------------------------------------`n"
        "Available Shares"
        "`n-------------------------------------`n"

        Get-WmiObject -class win32_share | Format-Table -AutoSize Name, Path, Description, Status | Out-String

        "`n-------------------------------------`n"
        "AV Solution"
        "`n-------------------------------------`n"

        $AV = Get-WmiObject -namespace root\SecurityCenter2 -class Antivirusproduct 
        if($AV){
            $AV.DisplayName + "`n"
            #No documentation from MSDN 
            #Best resource found : http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
            $AVstate = $AV.productState
            $statuscode = "{0:x6}" -f $AVstate
            $wscprovider = $statuscode[0,1]
            $wscscanner = $statuscode[2,3]
            $wscuptodate = $statuscode[4,5]
            $statuscode = -join $statuscode

            "AV Product State: " + $AV.productState + "`n"
            #check if the AV is enabled

            if($wscscanner -ge '10'){
                "Enabled: Yes`n"
            }
            elseif($wscscanner -eq '00' -or $wscscanner -eq '01'){
                "Enabled: No`n"
            }
            else{
                "Enabled: Unknown`n"
            }
            #Check if definitions are up to date
            if($wscuptodate -eq '00'){
                "Updated: Yes`n"
            }
            elseif($wscuptodate -eq '10'){
                "Updated: No`n"
            }
            else{
                "Updated: Unknown`n"
            }
        }
        
        "`n-------------------------------------`n"
        "Windows Last Updated"
        "`n-------------------------------------`n"
        $Lastupdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object InstalledOn -First 1
        if($Lastupdate){
           $Lastupdate.InstalledOn | Out-String
           "`n"
        }
        else{
            "Unknown`n" 
        }    


    }

    
    Function Get-NetInfo{
        "`n-------------------------------------`n"
        "Network Adapters"
        "`n-------------------------------------`n"
        #http://thesurlyadmin.com/2013/05/20/using-powershell-to-get-adapter-information/
        foreach ($Adapter in (Get-WmiObject -class win32_networkadapter -Filter "NetConnectionStatus='2'")){
            $config = Get-WmiObject -class win32_networkadapterconfiguration -Filter "Index = '$($Adapter.Index)'"
            "`n"
            "Adapter: " + $Adapter.Name + "`n"
            "`n"
            "IP Address: "
            if($config.IPAddress -is [system.array]){
                $config.IPAddress[0] + "`n"
            }
            else{
                $config.IPAddress + "`n"
            }
            "`n"
            "Mac Address: " + $Config.MacAddress
            "`n"
        }

        "`n-------------------------------------`n"
        "Netstat Established connections and processes"
        "`n-------------------------------------`n"
        #http://blogs.microsoft.co.il/scriptfanatic/2011/02/10/how-to-find-running-processes-and-their-port-number/

        $properties = 'Protocol','LocalAddress','LocalPort' 
        $properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

        netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {

            $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)

            if($item[1] -notmatch '^\[::') 
            {            
                if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
                { 
                    $localAddress = $la.IPAddressToString 
                    $localPort = $item[1].split('\]:')[-1] 
                } 
                else 
                { 
                    $localAddress = $item[1].split(':')[0] 
                    $localPort = $item[1].split(':')[-1] 
                } 

                if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
                { 
                    $remoteAddress = $ra.IPAddressToString 
                    $remotePort = $item[2].split('\]:')[-1] 
                } 
                else 
                { 
                    $remoteAddress = $item[2].split(':')[0] 
                    $remotePort = $item[2].split(':')[-1] 
                } 

                $netstat = New-Object PSObject -Property @{ 
                    PID = $item[-1] 
                    ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                    Protocol = $item[0] 
                    LocalAddress = $localAddress 
                    LocalPort = $localPort 
                    RemoteAddress =$remoteAddress 
                    RemotePort = $remotePort 
                    State = if($item[0] -eq 'tcp') {$item[3]} else {$null} 
                }
                if($netstat.State -eq 'ESTABLISHED' ){
                    $netstat | Format-List ProcessName,LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Out-String | % { $_.Trim() }
                    "`n`n"
                }
            }
        }
    

        "`n-------------------------------------`n"
        "Mapped Network Drives"
        "`n-------------------------------------`n"

        Get-WmiObject -class win32_logicaldisk | where-object {$_.DeviceType -eq 4} | ForEach-Object{
            $NetPath = $_.ProviderName
            $DriveLetter = $_.DeviceID
            $DriveName = $_.VolumeName
            $NetworkDrive = New-Object PSObject -Property @{
                Path = $NetPath
                Drive = $DriveLetter
                Name = $DriveName
            }
            $NetworkDrive
        }


        "`n-------------------------------------`n"
        "Firewall Rules"
        "`n-------------------------------------`n"
        #http://blogs.technet.com/b/heyscriptingguy/archive/2010/07/03/hey-scripting-guy-weekend-scripter-how-to-retrieve-enabled-windows-firewall-rules.aspx
        #Create the firewall com object to enumerate 
        $fw = New-Object -ComObject HNetCfg.FwPolicy2 
        #Retrieve all firewall rules 
        $FirewallRules = $fw.rules 
        #create a hashtable to define all values
        $fwprofiletypes = @{1GB="All";1="Domain"; 2="Private" ; 4="Public"}
        $fwaction = @{1="Allow";0="Block"}
        $FwProtocols = @{1="ICMPv4";2="IGMP";6="TCP";17="UDP";41="IPV6";43="IPv6Route"; 44="IPv6Frag";
                  47="GRE"; 58="ICMPv6";59="IPv6NoNxt";60="IPv60pts";112="VRRP"; 113="PGM";115="L2TP"}
        $fwdirection = @{1="Inbound"; 2="Outbound"} 

        #Retrieve the profile type in use and the current rules

        $fwprofiletype = $fwprofiletypes.Get_Item($fw.CurrentProfileTypes)
        $fwrules = $fw.rules

        "Current Firewall Profile Type in use: $fwprofiletype"
        $AllFWRules = @()
        #enumerate the firewall rules
        $fwrules | ForEach-Object{
            #Create custom object to hold properties for each firewall rule 
            $FirewallRule = New-Object PSObject -Property @{
                ApplicationName = $_.Name
                Protocol = $fwProtocols.Get_Item($_.Protocol)
                Direction = $fwdirection.Get_Item($_.Direction)
                Action = $fwaction.Get_Item($_.Action)
                LocalIP = $_.LocalAddresses
                LocalPort = $_.LocalPorts
                RemoteIP = $_.RemoteAddresses
                RemotePort = $_.RemotePorts
            }

            $AllFWRules += $FirewallRule

            
        } 
        $AllFWRules | Select-Object Action, Direction, RemoteIP, RemotePort, LocalPort, ApplicationName | Format-List | Out-String  
    }

    Get-UserInfo
    Get-SysInfo
    Get-NetInfo



}