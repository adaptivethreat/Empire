function Invoke-ThreadedFunction
{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String[]]$ComputerName,
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,
        [Parameter(Position = 2)]
        [Hashtable]$ScriptParameters,
        [Int]$Threads = 20,
        [Int]$Timeout = 100
    )
    
    begin
    {
        
        if ($PSBoundParameters['Debug'])
        {
            $DebugPreference = 'Continue'
        }
        
        Write-Verbose "[*] Total number of hosts: $($ComputerName.count)"
        
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        
        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!
        # create a pool of maxThread runspaces
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()
        
        $Jobs = @()
        $PS = @()
        $Wait = @()
        
        $Counter = 0
    }
    
    process
    {
        
        ForEach ($Computer in $ComputerName)
        {
            
            # make sure we get a server name
            if ($Computer -ne '')
            {
                
                While ($($Pool.GetAvailableRunspaces()) -le 0)
                {
                    Start-Sleep -MilliSeconds $Timeout
                }
                
                # create a "powershell pipeline runner"
                $PS += [powershell]::create()
                $PS[$Counter].runspacepool = $Pool
                
                # add the script block + arguments
                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
                if ($ScriptParameters)
                {
                    ForEach ($Param in $ScriptParameters.GetEnumerator())
                    {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }
                
                # start job
                $Jobs += $PS[$Counter].BeginInvoke();
                
                # store wait handles for WaitForAll call
                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }
    
    end
    {
        
        Write-Verbose "Waiting for scanning threads to finish..."
        $WaitTimeout = Get-Date
        
        # set a 60 second timeout for the scanning threads
        while ($($Jobs | Where-Object { $_.IsCompleted -eq $False }).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60)
        {
            Start-Sleep -MilliSeconds $Timeout
        }
        
        # end async call
        for ($y = 0; $y -lt $Counter; $y++)
        {
            
            try
            {
                # complete async job
                $PS[$y].EndInvoke($Jobs[$y])
                
            }
            catch
            {
                Write-Warning "error: $_"
            }
            finally
            {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose "All threads completed!"
    }
}

function Find-Fruit 

{

<#
.SYNOPSIS

Search for "low hanging fruit".
.DESCRIPTION

A script to find potentially easily exploitable web servers on a target network.

.PARAMETER Rhosts

Targets in CIDR or comma separated format.

.PARAMETER Port

Specifies the port to connect to.

.PARAMETER Path

Path to custom dictionary.

.PARAMETER Timeout

Timeout for each connection in milliseconds.

.PARAMETER UseSSL

Use an SSL connection.

.PARAMETER Threads

The maximum concurrent threads to execute.

.PARAMETER NoPing

Disable Ping Check

.PARAMETER FoundOnly

Only display found URI's

.EXAMPLE

C:\PS> Find-Fruit -Rhosts 192.168.1.0/24 -Port 8080 -Timeout 50
C:\PS> Find-Fruit -Rhosts 192.168.1.0/24 -Path dictionary.txt -Port 443 -Timeout 50


.NOTES
Credits to mattifestation for Get-HttpStatus
HTTP Status Codes: 100 - Informational * 200 - Success * 300 - Redirection * 400 - Client Error * 500 - Server Error
    

#>
    
[CmdletBinding()]

param (
    [Parameter(Mandatory = $True)]
    [String]$Rhosts,
    [Int]$Port,
    [String]$Path,
    [Int]$Timeout = 110,
    [Switch]$UseSSL,
    [ValidateRange(1, 100)]
    [Int]$Threads,
    [Switch]$NoPing,
    [Switch]$FoundOnly
)
    
    begin
    {   
        $hostList = New-Object System.Collections.ArrayList
        
        $iHosts = $Rhosts -split ","
        
        foreach ($iHost in $iHosts)
        {
            $iHost = $iHost.Replace(" ", "")
            
            if (!$iHost)
            {
                continue
            }
            
            if ($iHost.contains("/"))
            {
                $netPart = $iHost.split("/")[0]
                [uint32]$maskPart = $iHost.split("/")[1]
                
                $address = [System.Net.IPAddress]::Parse($netPart)
                if ($maskPart -ge $address.GetAddressBytes().Length * 8)
                {
                    throw "Bad host mask"
                }
                
                $numhosts = [System.math]::Pow(2, (($address.GetAddressBytes().Length * 8) - $maskPart))
                
                $startaddress = $address.GetAddressBytes()
                [array]::Reverse($startaddress)
                
                $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
                [uint32]$startMask = ([System.math]::Pow(2, $maskPart) - 1) * ([System.Math]::Pow(2, (32 - $maskPart)))
                $startAddress = $startAddress -band $startMask
                #in powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
                $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
                [array]::Reverse($startaddress)
                $address = [System.Net.IPAddress][byte[]]$startAddress
                
                $Null = $hostList.Add($address.IPAddressToString)
                
                for ($i = 0; $i -lt $numhosts - 1; $i++)
                {
                    $nextAddress = $address.GetAddressBytes()
                    [array]::Reverse($nextAddress)
                    $nextAddress = [System.BitConverter]::ToUInt32($nextAddress, 0)
                    $nextAddress++
                    $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                    [array]::Reverse($nextAddress)
                    $address = [System.Net.IPAddress][byte[]]$nextAddress
                    $Null = $hostList.Add($address.IPAddressToString)
                    
                }
                
            }
            else
            {
                $Null = $hostList.Add($iHost) 
            }
        }
            
        $HostEnumBlock = {
            param($ComputerName, $UseSSL, $Port, $Path, $Timeout, $FoundOnly)
            
            if ($UseSSL -and $Port -eq 0)
            {
                # Default to 443 if SSL is specified but no port is specified
                $Port = 443
            }
            elseif ($Port -eq 0)
            {
                # Default to port 80 if no port is specified
                $Port = 80
            }
            
            
            if ($UseSSL)
            {
                $SSL = 's'
                # Ignore invalid SSL certificates
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
            }
            else
            {
                $SSL = ''
            }
            
            if (($Port -eq 80) -or ($Port -eq 443))
            {
                $PortNum = ''
            }
            else
            {
                $PortNum = ":$Port"
            }
            
            if ($Path)
            {
                if (!(Test-Path -Path $Path)) { Throw "File doesnt exist" }
                $VulnLinks = @()
                foreach ($Link in Get-Content $Path)
                {
                    $VulnLinks = $VulnLinks + $Link
                }
            }
            else
            {
                $VulnLinks = @()
                $VulnLinks = $VulnLinks + "jmx-console/" # Jboss
                $VulnLinks = $VulnLinks + "web-console/ServerInfo.jsp" # Jboss
                $VulnLinks = $VulnLinks + "invoker/JMXInvokerServlet" # Jboss
                $VulnLinks = $VulnLinks + "lc/system/console" # Adobe LiveCycle OSGi console
                $VulnLinks = $VulnLinks + "axis2/axis2-admin/" # Apache Axis2
                $VulnLinks = $VulnLinks + "manager/html/" # Tomcat
                $VulnLinks = $VulnLinks + "tomcat/manager/html/" # Tomcat
                $VulnLinks = $VulnLinks + "wp-admin" # Wordpress
                $VulnLinks = $VulnLinks + "workorder/FileDownload.jsp" #Manage Engine
                $VulnLinks = $VulnLinks + "ibm/console/logon.jsp?action=OK" # WebSphere
                $VulnLinks = $VulnLinks + "data/login" # Dell iDrac
                $Vulnlinks = $Vulnlinks + "CFIDE/administrator/index.cfm" #ColdFusion
            }
            
            # Check Http status for each entry in the ditionary file
            foreach ($Target in $ComputerName)
            {
                                
                
                foreach ($Item in $Vulnlinks)
                {
                    
                    $WebTarget = "http$($SSL)://$($Target)$($PortNum)/$($Item)"
                    $URI = New-Object Uri($WebTarget)
                    
                    try
                    {
                        $WebRequest = [System.Net.WebRequest]::Create($URI)
                        $WebResponse = $WebRequest.Timeout = $Timeout
                        $WebResponse = $WebRequest.GetResponse()
                        $WebStatus = $WebResponse.StatusCode
                        $ResultObject += $ScanObject
                        $WebResponse.Close()
                    }
                    catch
                    {
                        $WebStatus = $Error[0].Exception.InnerException.Response.StatusCode
                        
                        if ($WebStatus -eq $null)
                        {
                            # Not every exception returns a StatusCode.
                            # If that is the case, return the Status.
                            $WebStatus = $Error[0].Exception.InnerException.Status
                        }
                    }

                    $Result = @{
                        Status = $WebStatus;
                        URL = $WebTarget
                    }
                    
                    if ($FoundOnly) {
                        New-Object -TypeName PSObject -Property $Result | Where-Object {$_.Status -eq 'OK'}
                                          
                    } else {
                        New-Object -TypeName PSObject -Property $Result
                    }
                    
                }
            }
        }
    }

    process {

        if(-not $NoPing -and ($hostList.count -ne 1)) {
            # ping all hosts in parallel
            $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
            $hostList = Invoke-ThreadedFunction -ComputerName $hostList -ScriptBlock $Ping -Threads 100
        }

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"

            # if we're using threading, kick off the script block with Invoke-ThreadedFunction
            $ScriptParams = @{
                'UseSSL' = $UseSSL
                'Port' = $Port
                'Path' = $Path
                'Timeout' = $Timeout
                'FoundOnly' = $FoundOnly
            }

            # kick off the threaded script block + arguments
            Invoke-ThreadedFunction -ComputerName $hostList -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $HostList, $UseSSL, $Port, $Path, $Timeout, $FoundOnly
        }
    }
}


