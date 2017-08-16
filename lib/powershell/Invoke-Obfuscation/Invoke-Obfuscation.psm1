#   This file is part of Invoke-Obfuscation.
#
#   Copyright 2017 Daniel Bohannon <@danielhbohannon>
#         while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



# Get location of this script no matter what the current directory is for the process executing this script.
$ScriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

Write-Host "`n[*] Invoke-Obfuscation.psm1 has been decomissioned." -ForegroundColor Red
Write-Host "[*] Please run" -NoNewLine -ForegroundColor Red
Write-Host " Import-Module $ScriptDir\Invoke-Obfuscation.psd1 " -NoNewLine -ForegroundColor Yellow
Write-Host "instead." -ForegroundColor Red



<#
.SYNOPSIS

PowerShell module file for importing all required modules for the Invoke-Obfuscation framework.

Invoke-Obfuscation Module Loader
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

PowerShell module file for importing all required modules for the Invoke-Obfuscation framework.

.EXAMPLE

C:\PS> Import-Module .\Invoke-Obfuscation.psm1

.NOTES

PowerShell module file for importing all required modules for the Invoke-Obfuscation framework.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
<#
# Confirm all necessary commands are loaded and import appropriate .ps1 files in current directory if necessary.
Write-Host "`n[*] Validating necessary commands are loaded into current PowerShell session.`n"

$RequiredFunctions  = @()
$RequiredFunctions += 'Out-ObfuscatedTokenCommand'
$RequiredFunctions += 'Out-ObfuscatedStringCommand'
$RequiredFunctions += 'Out-EncodedAsciiCommand'
$RequiredFunctions += 'Out-EncodedHexCommand'
$RequiredFunctions += 'Out-EncodedOctalCommand'
$RequiredFunctions += 'Out-EncodedBinaryCommand'
$RequiredFunctions += 'Out-SecureStringCommand'
$RequiredFunctions += 'Out-EncodedBXORCommand'
$RequiredFunctions += 'Out-PowerShellLauncher'
$RequiredFunctions += 'Invoke-Obfuscation'

# Get location of this script no matter what the current directory is for the process executing this script.
$ScriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

$UnloadedFunctionExists = $FALSE
ForEach($Function in $RequiredFunctions)
{
    # Check if $Function is loaded.
    If(!(Get-Command * | Where-Object {$_.Name -like $Function}))
    {
        # Validate that appropriate .ps1 file exists.
        If(Test-Path $ScriptDir\$Function.ps1)
        {
            # Import module.
            Import-Module $ScriptDir\$Function.ps1
            
            # Re-check if $Function is loaded.
            If((Get-Command * | Where-Object {$_.Name -like $Function}).Name)
            {
                Write-Host "[*] Function Loaded :: $Function" -ForegroundColor Green
            }
            Else
            {
                Write-Host "[*] Function Not Loaded :: $Function (After running Import-Module $ScriptDir\$Function.ps1)" -ForegroundColor Red
                $UnloadedFunctionExists = $TRUE
            }
        }
        Else {
            Write-Host "[*] Function Not Loaded :: $Function (Cannot locate $ScriptDir\$Function.ps1)" -ForegroundColor Red
            $UnloadedFunctionExists = $TRUE
        }
    }
    Else {
        Write-Host "[*] Function Already Loaded :: $Function" -ForegroundColor Green
    }
}

# Show error and warning if any functions were not properly loaded.
If($UnloadedFunctionExists)
{
    Write-Host "`n[*] One or more above functions are not loaded." -ForegroundColor Red
    Write-Host "    Ensure Invoke-Obfuscation.psm1 is in the same directory as above scripts.`n" -ForegroundColor Red
}
Else
{
    Write-Host "`n[*] All modules loaded and ready to run " -NoNewLine
    
    # Write output below string in interactive format.
    ForEach($Char in [Char[]]'Invoke-Obfuscation')
    {
        Write-Host $Char -NoNewline -ForegroundColor Green
        Start-Sleep -Milliseconds (Get-Random -Input @(25..200))
    }
    Start-Sleep -Milliseconds 500
    Write-Host "`n"
}
#>