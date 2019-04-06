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



Function Out-SecureStringCommand
{
<#
.SYNOPSIS

Generates AES-encrypted SecureString object out of three possible syntaxes for a PowerShell command or script. Optionally it adds command line output to final command.

Invoke-Obfuscation Function: Out-SecureStringCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-SecureStringCommand encrypts an input PowerShell scriptblock or path as a SecureString object. It randomly selects between three different syntaxes for accomplishing this. The purpose is to highlight to the Blue Team that there are more novel ways to encode/encrypt a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER NoExit

Outputs the option to not exit after running startup commands.

.PARAMETER NoProfile

Outputs the option to not load the Windows PowerShell profile.

.PARAMETER NonInteractive

Outputs the option to not present an interactive prompt to the user.

.PARAMETER NoLogo

Outputs the option to not present the logo to the user.

.PARAMETER Wow64

Calls the x86 (Wow64) version of PowerShell on x86_64 Windows installations.

.PARAMETER Command

Outputs the option to execute the specified commands (and any parameters) as though they were typed at the Windows PowerShell command prompt.

.PARAMETER WindowStyle

Outputs the option to set the window style to Normal, Minimized, Maximized or Hidden.

.PARAMETER ExecutionPolicy

Outputs the option to set the default execution policy for the current session.

.PARAMETER PassThru

(Optional) Avoids applying final command line syntax if you want to apply more obfuscation functions (or a different launcher function) to the final output.

.EXAMPLE

C:\PS> Out-SecureStringCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive

powershell  -NoProfi -NonIn     " IEX( ([Runtime.InteropServices.Marshal]::PtrToStringUni( [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode( $('76492d1116743f0423413b16050a5345MgB8AG0AOQBKAEcAZgBHAEwAaQBBADkAbABoAFQASgBGAGEATgBBAFUAOABIAGcAPQA9AHwAYwBmADEAZgA4ADQAYgAyADkAZgBjADcAOABiAGYAYgBkADAAZAA5AGMAMgBlADgAZQBjADIAOAAxADYAOQBhADYANQBkADYANQA3ADEAMAAwADQAMwBjADgAMAA1AGMAZAAwADYAOQAxAGIAMQA5ADYAYwAwADQAMAA1AGEAOAA5ADEANwA1ADgANgA5ADEANABhAGQAMABhAGEANwAxAGUAZgBjADcAZABiADMAYgBlADgAYQBhAGIAMAAyADIANwA2AGYAYwBhAGQANwA0ADkAOAA2ADEAMAA0ADIAYQBkAGYAMAA5ADgAMwAzAGEAYwBmADYANQA5ADAANQA0ADcAYgAwADEANAAyADgAMwBmADUAMQAzADAAMQBmADAAZABkAGIAOQAxAGIAZQAxADIAZQA2ADIAMgAxADgAOAA5ADEANgA1AGEANgA2AGEAZABjADcAZQAwAGIANgBmADEANgA2ADAAMwBjADEANQAzAGUAZgBkADUAYQAwADYAMgBmAGMAOAAxAGUANgBmADgAYwA5ADUAZgBlADMANAA1ADQANQA3ADIANgA2ADYAOQBlAGUANwBkAGUAYQAyAGIAZAA2AGUAZgBiADUANwA4AGQANQA5ADIANgBjADMAZgBlADUANQA4AGMAOQBjADcANQA2ADEAYwA3ADQAYwAzAGUAZAA4ADkAOABlAGYANAA5AGUAZQAwADYAMgAxAGEAZgA2ADIAOABkAGYANwA4AGIAOAA1ADQANgA2ADIAYgBkAGQANAA4AGYANwA4AGYAYQBmAGIAZAAyAGMAYgBiADkANQBlADIAYwAyADYANABkADgAMgA2AGIAZQBlADIAZQBlAGUAOQA0AGIANgAxADIAZgA0ADIAOQBmADAAYwBmADIAOQBmAGYANgBlAGUAZAA3ADMAMAA0ADMAYwBjADQAMgBhAGIAZgA4ADAAMQA1ADYAOQA5AGYAZQA4AGIAMwBhAGMAOQAyADcAYwA2AGQAMgBmAGYANwA4AGQAOABiADAAZQBmADcANgBlAGIAMwBiADgAMwAxADcAZQBlAGQAYQBmAGYAYgBmAGIAYQA5AGEAYQBhAGQAOAA5AGQAZgAwAGMAMgAwAGUANQBlADcAOQA5ADAAZgBkADkAZAAwADMAYQBhADIAZAA0ADcAOQBkADAANgA1ADUAOAA=' |ConvertTo-SecureString -Key  241,131,91,52,14,165,71,51,19,86,1,104,87,220,235,62) ))) )"

C:\PS> Out-SecureStringCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive -PassThru

(New-Object  Management.Automation.PSCredential ' ', ( '76492d1116743f0423413b16050a5345MgB8AEUAcQBKAHkAegBqAHUAQwBNAC8AeABPAHUAbgBlADAAUABMAHQARQAyAGcAPQA9AHwAMgBlAGEANQBiADMAMAA0ADMANQBkAGIAMQA2AGUAYwA2ADIANwAyADEANAA5ADUAYwAyADkAOAAzADUAZAAwADcANAAwADQAOQA0AGQAZQAwADUAYwBjADUAZgAwADYAYgA0AGIAYQA0AGYANwAxADUAMwA1AGUANQAxAGMANwBiADAANgA3ADgAOABmAGQAYwBjADYAMAA4AGYAZQAyADEAZAAyADQAMgBkAGYAYwBmADkAZQA5ADkAMwBmAGMAZAAzADgAOQAwADEANQBhADcANAA5AGUANQBiAGMAOAA2ADYAOAAxAGYAMwAxAGYAMwA4AGQANAA0ADAAYgA3ADUAMwBkADcAMQAwADAANABlAGIAOQAxAGIAOQAxADcAZgBjAGEANAA4ADUAOQBlADUAOAA1AGEANwBjADUAYQAwADgAOAAyAGEAMAAzADQAMQA3ADYAMwA0AGUAMwBiADUAZgA3AGMAMwA5AGQAZQAyADkAMgAxADAAMgA5ADUAMwBmADMAOAA5ADQAYwAyAGUANwA5AGMAMgA5ADEAMAAwAGEAMgAyAGQANQA4ADAAZQBiAGMAZAA1ADkAMgBlAGQAOAAyADIAZAA3ADQAYQBmADIANwAwADQAMQAzADQANgAxADQAMwA5ADgANQBlADIANQA2ADEAMwBiAGUAMwBhAGMAMQAwADIAYQBjAGMAYgA5AGUAYQBjAGQAZQAyADYAYgAyADkAZABjAGEAMAA4ADIANAA1AGMAOAAzADgAZgAyAGEAMABlAGYANAAwAGEAMgAyADgANQBlADkAMgAyAGEANgA0ADQANwBlADAAYgA0ADkAMgBkAGMANgAwAGMANwA3ADUAZABhADkAMgA1ADAAYgA0ADgAYQBmAGIAMQBjADEAMgA2ADEAZgA0ADkANgA4AGYAMQA0ADkAMAA0AGYANwBjAGMAYQBiAGQAZQA4ADIAMAA1AGUAZgA4ADMAZQAwAGMAYQBlADQAMgBkAGIAOQBkADUANwAzADQANwAyAGIAYwAxADQAYwBiAGEAZAA2AGYAZQAzADUAYgAxADgAYgBhADcANQAyADkAMAAwADcAMAA0ADQANgBlAGMAYQA1ADQAMQBhAGYAYgAzADYANwBjAGIAZgAyAGEAYgBkADgAZAAwAGEAZgBmADYAMQA2AGIAMAA1AGIANQA=' |ConvertTo-SecureString  -Key  205,39,9,9,104,139,104,94,252,20,93,132,29,171,56,2 )).GetNetworkCredential().Password | Invoke-Expression

.NOTES

The size limit for a single SecureString object input is 65,536 characters. However, this will consume significant resources on the target system when decoding a SecureString object of this size (50% CPU and ~30 seconds on several test VMs). For larger payloads I would recommend chunking your payload and encoding/encrypting each piece separately and then reassembling each decoded/decrypted piece during runtime. I have a POC that does this and will be releasing a STAGING set of functions soon to accomplish this very task.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Switch]
        $NoExit,

        [Switch]
        $NoProfile,

        [Switch]
        $NonInteractive,

        [Switch]
        $NoLogo,

        [Switch]
        $Wow64,

        [Switch]
        $Command,

        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,

        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        
        [Switch]
        $PassThru
    )

    # Either convert ScriptBlock to a String or convert script at $Path to a String.
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }

    # Convert $ScriptString to a SecureString object.
    $SecureString = ConvertTo-SecureString $ScriptString -AsPlainText -Force
    
    # Randomly select the key length. Supported key lengths for SecureString (AES) are 16, 24 and 32.
    $KeyLength = Get-Random @(16,24,32)
    
    # Randomly select the key value and how it will be formatted.
    Switch(Get-Random -Minimum 1 -Maximum 3)
    { 
        1 {
            # Generate random key of length $KeyLength.
            $SecureStringKey = @()
            For($i=0; $i -lt $KeyLength; $i++) {
                $SecureStringKey += Get-Random -Minimum 0 -Maximum 256
            }
            $SecureStringKeyStr = $SecureStringKey -Join ','
          }
        2 {
            # Generate sequential key of length $KeyLength with random array bounds.
            # To save space use shorthand array notation in final command with $SecureStringKeyStr.
            $LowerBound = (Get-Random -Minimum 0 -Maximum (256-$KeyLength))
            $UpperBound = $LowerBound + ($KeyLength - 1)
            Switch(Get-Random @('Ascending','Descending'))
            {
                'Ascending'  {$SecureStringKey = ($LowerBound..$UpperBound); $SecureStringKeyStr = "($LowerBound..$UpperBound)"}
                'Descending' {$SecureStringKey = ($UpperBound..$LowerBound); $SecureStringKeyStr = "($UpperBound..$LowerBound)"}
                default {Write-Error "An invalid array ordering option was generated for switch block."; Exit;}
            }
          }
        default {Write-Error "An invalid random number was generated for switch block."; Exit;}
    }
    
    # Convert SecureString object to text that we can load on target system.
    $SecureStringText = $SecureString | ConvertFrom-SecureString -Key $SecureStringKey

    # Generate random syntax for -Key command argument.
    $Key = (Get-Random -Input @(' -Key ',' -Ke ',' -K '))

    # Randomly choose member invocation syntax. ".Invoke" syntax below is not necessary for PS 3.0+
    $PtrToStringAuto = (Get-Random -Input @('PtrToStringAuto',('([Runtime.InteropServices.Marshal].GetMembers()[' + (Get-Random -Input @(3,5)) + '].Name).Invoke')))
    $PtrToStringUni  = (Get-Random -Input @('PtrToStringUni' ,('([Runtime.InteropServices.Marshal].GetMembers()[' + (Get-Random -Input @(2,4)) + '].Name).Invoke')))
    $PtrToStringAnsi = (Get-Random -Input @('PtrToStringAnsi',('([Runtime.InteropServices.Marshal].GetMembers()[' + (Get-Random -Input @(0,1)) + '].Name).Invoke')))
    # Below four notations are commented out as they only work on PS 3.0+
    #$PtrToStringBSTR                  = (Get-Random -Input @('PtrToStringBSTR'                 ,'([Runtime.InteropServices.Marshal].GetMembers()[142].Name).Invoke'))
    #$SecureStringToBSTR               = (Get-Random -Input @('SecureStringToBSTR'              ,'([Runtime.InteropServices.Marshal].GetMembers()[162].Name)'))
    #$SecureStringToGlobalAllocUnicode = (Get-Random -Input @('SecureStringToGlobalAllocUnicode','([Runtime.InteropServices.Marshal].GetMembers()[169].Name)'))
    #$SecureStringToGlobalAllocAnsi    = (Get-Random -Input @('SecureStringToGlobalAllocAnsi'   ,'([Runtime.InteropServices.Marshal].GetMembers()[168].Name)'))

    # Randomize the case versions for necessary operations.
    $PtrToStringAuto                  = ([Char[]]"[Runtime.InteropServices.Marshal]::$PtrToStringAuto("                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PtrToStringUni                   = ([Char[]]"[Runtime.InteropServices.Marshal]::$PtrToStringUni("                  | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PtrToStringAnsi                  = ([Char[]]"[Runtime.InteropServices.Marshal]::$PtrToStringAnsi("                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PtrToStringBSTR                  = ([Char[]]'[Runtime.InteropServices.Marshal]::PtrToStringBSTR('                  | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SecureStringToBSTR               = ([Char[]]'[Runtime.InteropServices.Marshal]::SecureStringToBSTR('               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SecureStringToGlobalAllocUnicode = ([Char[]]'[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode(' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SecureStringToGlobalAllocAnsi    = ([Char[]]'[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocAnsi('    | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $NewObject                        = ([Char[]]'New-Object '                                                          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PSCredential                     = ([Char[]]'Management.Automation.PSCredential '                                  | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ConvertToSecureString            = ([Char[]]'ConvertTo-SecureString'                                               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Key                              = ([Char[]]$Key                                                                   | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $GetNetworkCredential             = ([Char[]]').GetNetworkCredential().Password'                                    | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''

    # Set syntax for running ConvertTo-SecureString cmdlet.
    $ConvertToSecureStringSyntax = '$(' + "'$SecureStringText'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureString + ' '*(Get-Random -Input @(0,1)) + $Key + ' '*(Get-Random -Input @(0,1)) + $SecureStringKeyStr + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')'

    # Generate the code that will decrypt and execute the payload and randomly select one.
    $NewScriptArray = @()
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringAuto + ' '*(Get-Random -Input @(0,1)) + $SecureStringToBSTR               + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringUni  + ' '*(Get-Random -Input @(0,1)) + $SecureStringToGlobalAllocUnicode + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringAnsi + ' '*(Get-Random -Input @(0,1)) + $SecureStringToGlobalAllocAnsi    + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringBSTR + ' '*(Get-Random -Input @(0,1)) + $SecureStringToBSTR               + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $NewObject + ' '*(Get-Random -Input @(0,1)) + $PSCredential + ' '*(Get-Random -Input @(0,1)) + "' '" + ',' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "'$SecureStringText'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureString + ' '*(Get-Random -Input @(0,1)) + $Key + ' '*(Get-Random -Input @(0,1)) + $SecureStringKeyStr + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + $GetNetworkCredential
    # Select random option from above.
    $NewScript = (Get-Random -Input $NewScriptArray)

    # Generate random invoke operation syntax.
    # Below code block is a copy from Out-ObfuscatedStringCommand.ps1. It is copied into this encoding function so that this will remain a standalone script without dependencies.
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out (and not sure that I ever will), these are included to highlight how IEX/Invoke-Expression is a great indicator but not a silver bullet.
    # These methods draw on common environment variable values and PowerShell Automatic Variable values/methods/members/properties/etc.
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    # Commenting below option since $env:Public differs in string value for non-English operating systems.
    #$InvokeExpressionSyntax += $InvocationOperator + "( `$env:Public[13]+`$env:Public[5]+'x')"

    # Randomly choose from above invoke operation syntaxes.
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)

    # Randomize the case of selected invoke operation.
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    
    # Generate random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    # Select random option from above.
    $NewScript = (Get-Random -Input $InvokeOptions)

    # If user did not include -PassThru flag then continue with adding execution flgs and powershell.exe to $NewScript.
    If(!$PSBoundParameters['PassThru'])
    {
        # Array to store all selected PowerShell execution flags.
        $PowerShellFlags = @()

        # Build the PowerShell execution flags by randomly selecting execution flags substrings and randomizing the order.
        # This is to prevent Blue Team from placing false hope in simple signatures for common substrings of these execution flags.
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}

            # Randomly decide to write WindowStyle value with flag substring or integer value.
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }

            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            # Take into account the shorted flag of -EP as well.
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        
        # Randomize the order of the execution flags.
        # This is to prevent the Blue Team from placing false hope in simple signatures for ordering of these flags.
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }

        # If selected then the -Command flag needs to be added last.
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }

        # Randomize the case of all command-line arguments.
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }

        # Random-sized whitespace between all execution flags and encapsulating final string of execution flags.
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)

        # Build up the full command-line string.
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            # Obfuscation isn't about saving space, and there are reasons you'd potentially want to fully path powershell.exe (more info on this soon).
            #$CommandLineOutput = "$($Env:windir)\System32\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }

        # Make sure final command doesn't exceed cmd.exe's character limit.
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        
        $NewScript = $CommandLineOutput
    }

    Return $NewScript
}