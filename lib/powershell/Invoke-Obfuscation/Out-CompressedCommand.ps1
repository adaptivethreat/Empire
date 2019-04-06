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



Function Out-CompressedCommand
{
<#
.SYNOPSIS

Generates compressed and base64 encoded payload for a PowerShell command or script. Optionally it adds command line output to final command.

Invoke-Obfuscation Function: Out-CompressedCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-CompressedCommand compresses an input PowerShell scriptblock or path and then base64 encodes the result. The purpose is to convert a multi-lined script into a one-liner command while also reducing the length for command-line character limit purposes.

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

C:\PS> Out-CompressedCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive

powershell  -NoProfil  -NonInteract     "& ( $EnV:COMSPEC[4,24,25]-Join'')((NEw-obJECt  Io.compRESSIon.defLATEStREAm( [SySTEM.iO.MeMoRYStreAM] [coNvERt]::FROmBASe64StrinG('Cy/KLEnV9cgvLlFQ90jNyclXCM8vyklRVFfQdcsvSk0vyi/NS3HOz8kvUnAvSk3Ns1YIR9Lhn5RWWpycWJKZn6cQlJ+cXYxTHwA=' ),[sYStem.io.CoMPreSsION.cOMpREsSIoNMOde]::DecOmPReSS )|ForEaCH {NEw-obJECt  SYStEm.io.sTReamrEADer($_ , [tEXT.eNCoDinG]::aSCii) } ).ReADTOend()) "

.EXAMPLE

C:\PS> Out-CompressedCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive -PassThru

&( $PShOmE[21]+$pshome[30]+'X')( (nEW-oBjEcT IO.COMpRESsion.DeFLaTEStrEam( [IO.MEmoRySTReam][converT]::frOMbaSE64STriNG( 'Cy/KLEnV9cgvLlFQ90jNyclXCM8vyklRVFfQdcsvSk0vyi/NS3HOz8kvUnAvSk3Ns1YIR9Lhn5RWWpycWJKZn6cQlJ+cXYxTHwA=' ) , [iO.ComPrEssion.COMPrESSIOnMoDE]::DECoMPREss) |FOreaCH { nEW-oBjEcT  IO.STrEAMreaDEr($_, [SYStEm.teXT.EncOdiNg]::Ascii) } |ForEACH {$_.ReaDTOend( ) }) )

.NOTES

Inspiration for this encoding technique came from Matt Graeber's (@mattifestation) Out-EncodedCommand: https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-EncodedCommand.ps1
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

    # Either convert ScriptBlock to bytes or convert script at $Path to bytes.
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllBytes((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
    }

    # Compress and base64 encode input $ScriptString.
    # These next 7 lines are copied directly from Matt Graeber's (@mattifestation) Out-EncodedCommand: https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-EncodedCommand.ps1#L116-L122
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptString, 0, $ScriptString.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    # Generate random case versions for necessary operations.
    $StreamReader     = Get-Random -Input @('IO.StreamReader','System.IO.StreamReader')
    $DeflateStream    = Get-Random -Input @('IO.Compression.DeflateStream','System.IO.Compression.DeflateStream')
    $MemoryStream     = Get-Random -Input @('IO.MemoryStream','System.IO.MemoryStream')
    $Convert          = Get-Random -Input @('Convert','System.Convert')
    $CompressionMode  = Get-Random -Input @('IO.Compression.CompressionMode','System.IO.Compression.CompressionMode')
    $Encoding         = Get-Random -Input @('Text.Encoding','System.Text.Encoding')
    $ForEachObject    = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StreamReader     = ([Char[]]$StreamReader      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $DeflateStream    = ([Char[]]$DeflateStream     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $MemoryStream     = ([Char[]]$MemoryStream      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Convert          = ([Char[]]$Convert           | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CompressionMode  = ([Char[]]$CompressionMode   | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Encoding         = ([Char[]]$Encoding          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $NewObject        = ([Char[]]'New-Object'       | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $FromBase64       = ([Char[]]'FromBase64String' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Decompress       = ([Char[]]'Decompress'       | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Ascii            = ([Char[]]'Ascii'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ReadToEnd        = ([Char[]]'ReadToEnd'        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject    = ([Char[]]$ForEachObject     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject2   = ([Char[]]$ForEachObject     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''

    # Break up the sub-components of the final command for easier re-ordering options to increase randomization.
    $Base64 = ' '*(Get-Random -Input @(0,1)) + "[$Convert]::$FromBase64(" + ' '*(Get-Random -Input @(0,1)) + "'$EncodedCompressedScript'" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1))
    $DeflateStreamSyntax = ' '*(Get-Random -Input @(0,1)) + "$DeflateStream(" + ' '*(Get-Random -Input @(0,1)) + "[$MemoryStream]$Base64," + ' '*(Get-Random -Input @(0,1)) + "[$CompressionMode]::$Decompress" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1))

    # Generate random syntax for all above options.
    $NewScriptArray   = @()
    $NewScriptArray  += "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject " + ' '*(Get-Random -Input @(0,1)) + "$StreamReader(" + ' '*(Get-Random -Input @(0,1)) + "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject $DeflateStreamSyntax)" + ' '*(Get-Random -Input @(0,1)) + "," + ' '*(Get-Random -Input @(0,1)) + "[$Encoding]::$Ascii)" + ' '*(Get-Random -Input @(0,1)) + ").$ReadToEnd(" + ' '*(Get-Random -Input @(0,1)) + ")"
    $NewScriptArray  += "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject $DeflateStreamSyntax|" + ' '*(Get-Random -Input @(0,1)) + "$ForEachObject" + ' '*(Get-Random -Input @(0,1)) + "{" + ' '*(Get-Random -Input @(0,1)) + "$NewObject " + ' '*(Get-Random -Input @(0,1)) + "$StreamReader(" + ' '*(Get-Random -Input @(0,1)) + "`$_" + ' '*(Get-Random -Input @(0,1)) + "," + ' '*(Get-Random -Input @(0,1)) + "[$Encoding]::$Ascii" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + "}" + ' '*(Get-Random -Input @(0,1)) + ").$ReadToEnd(" + ' '*(Get-Random -Input @(0,1)) + ")"
    $NewScriptArray  += "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject $DeflateStreamSyntax|" + ' '*(Get-Random -Input @(0,1)) + "$ForEachObject" + ' '*(Get-Random -Input @(0,1)) + "{" + ' '*(Get-Random -Input @(0,1)) + "$NewObject " + ' '*(Get-Random -Input @(0,1)) + "$StreamReader(" + ' '*(Get-Random -Input @(0,1)) + "`$_" + ' '*(Get-Random -Input @(0,1)) + "," + ' '*(Get-Random -Input @(0,1)) + "[$Encoding]::$Ascii" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + "}" + ' '*(Get-Random -Input @(0,1)) + "|" + ' '*(Get-Random -Input @(0,1)) + "$ForEachObject2" + ' '*(Get-Random -Input @(0,1)) + "{" + ' '*(Get-Random -Input @(0,1)) + "`$_.$ReadToEnd(" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + "}" + ' '*(Get-Random -Input @(0,1)) + ")"
    
    # Randomly select one of the above commands.
    $NewScript = (Get-Random -Input $NewScriptArray)

    # Generate random invoke operation syntax.
    # Below code block is a copy from Out-ObfuscatedStringCommand.ps1. It is copied into this encoding function so that this will remain a standalone script without dependencies.
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out, these are included to highlight how IEX/Invoke-Expression is a great indicator but not a silver bullet.
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
    
    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression

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
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = 0}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = 1}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = 2}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = 3}}
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
            $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
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