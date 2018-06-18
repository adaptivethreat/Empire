param($Token,$Channel,$ThreadTS)

Function Execute-HTTPPostCommand()
{
  param(
    [string] $url = $null,
    [string] $data = $null,
    [System.Net.NetworkCredential]$credentials = $null,
    [string] $contentType = "application/x-www-form-urlencoded",
    [string] $codePageName = "UTF-8",
    [string] $userAgent = $null
  );

  if ( $url -and $data )
  {
    [System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($url);
    $webRequest.ServicePoint.Expect100Continue = $false;
    if ( $credentials )
    {
      $webRequest.Credentials = $credentials;
      $webRequest.PreAuthenticate = $true;
    }
    $webRequest.ContentType = $contentType;
    $webRequest.Method = "POST";
    if ( $userAgent )
    {
      $webRequest.UserAgent = $userAgent;
    }

    $enc = [System.Text.Encoding]::GetEncoding($codePageName);
    [byte[]]$bytes = $enc.GetBytes($data);
    $webRequest.ContentLength = $bytes.Length;
    [System.IO.Stream]$reqStream = $webRequest.GetRequestStream();
    $reqStream.Write($bytes, 0, $bytes.Length);
    $reqStream.Flush();

    $resp = $webRequest.GetResponse();
    $rs = $resp.GetResponseStream();
    [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
    $sr.ReadToEnd();
  }
}


function ConvertTo-Json20([object] $item){
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return $ps_js.Serialize($item)
}

function ConvertFrom-Json20([object] $item){ 
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
}

ConvertFrom-Json20 (Execute-HTTPPostCommand -Url https://slack.com/api/channels.history -data "token=$Token&channel=$Channel&oldest=$ThreadTS&inclusive=true")