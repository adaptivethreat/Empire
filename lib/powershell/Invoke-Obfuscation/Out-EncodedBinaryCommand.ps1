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



Function Out-EncodedBinaryCommand
{
<#
.SYNOPSIS

Generates binary encoded payload for a PowerShell command or script. Optionally it adds command line output to final command.

Invoke-Obfuscation Function: Out-EncodedBinaryCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncodedBinaryCommand encodes an input PowerShell scriptblock or path as a binary payload. It randomly chooses between .Split/-Split/array syntax to store the encoded payload in the final output. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

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

C:\PS> Out-EncodedBinaryCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive

powershell   -NonIn  -NoProf     "-Join ('1010111y1110010W1101001{1110100G1100101y101101;1001000T1101111@1110011G1110100y100000@100111y1001000@1100101d1101100<1101100b1101111d100000W1010111@1101111G1110010{1101100@1100100@100001<100111G100000y101101;1000110;1101111y1110010G1100101d1100111y1110010G1101111@1110101W1101110b1100100G1000011;1101111d1101100{1101111y1110010d100000<1000111<1110010T1100101W1100101@1101110d111011{100000T1010111{1110010{1101001{1110100y1100101b101101<1001000y1101111{1110011W1110100d100000d100111b1001111<1100010b1100110<1110101d1110011W1100011W1100001T1110100T1101001{1101111;1101110W100000T1010010b1101111<1100011W1101011;1110011;100001d100111@100000y101101<1000110T1101111G1110010{1100101W1100111{1110010G1101111d1110101W1101110@1100100@1000011{1101111d1101100y1101111T1110010{100000{1000111{1110010T1100101b1100101;1101110'-SplIt'b'-SpLit '@'-SPLIt '{' -SpLIT'<'-SPLIT'd' -SpLIT 'T'-SplIt ';' -SpLiT 'G' -SPLiT'y'-SpLiT'W' | ForEach-Object { ([Char]([Convert]::ToInt16(( $_.ToString() ) ,2) ))} )| IEX"

C:\PS> Out-EncodedBinaryCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive -PassThru

IEX( -Join ('1010111<1110010>1101001a1110100>1100101r101101{1001000@1101111l1110011l1110100a100000<100111m1001000r1100101{1101100{1101100{1101111>100000{1010111>1101111>1110010m1101100O1100100a100001O100111&100000@101101&1000110<1101111a1110010&1100101&1100111O1110010r1101111r1110101<1101110O1100100m1000011{1101111>1101100m1101111{1110010m100000{1000111a1110010>1100101>1100101m1101110&111011O100000r1010111&1110010l1101001{1110100{1100101r101101@1001000&1101111>1110011<1110100&100000>100111a1001111{1100010a1100110@1110101{1110011&1100011r1100001@1110100l1101001>1101111a1101110a100000@1010010a1101111r1100011a1101011m1110011{100001<100111a100000{101101@1000110a1101111{1110010m1100101a1100111>1110010l1101111m1110101l1101110@1100100r1000011&1101111r1101100O1101111m1110010a100000@1000111@1110010O1100101@1100101@1101110'.Split( 'l@>{r<mOa&') | ForEach-Object{ ( [Convert]::ToInt16(( [String]$_ ) , 2 ) -As[Char]) } ))

.NOTES

Inspiration for this encoding technique came from: https://blogs.technet.microsoft.com/heyscriptingguy/2011/09/09/convert-hexadecimal-to-ascii-using-powershell/
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

    # Encoding base values: 16=Hex, 8=Octal, 2=Binary
    $EncodingBase = 2

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

    # Create list of random delimiters $RandomDelimiters.
    # Avoid using . * ' " [ ] ( ) etc. as delimiters as these will cause problems in the -Split command syntax.
    $RandomDelimiters  = @('_','-',',','{','}','~','!','@','%','&','<','>',';',':')

    # Add letters a-z with random case to $RandomDelimiters.
    @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') | ForEach-Object {$UpperLowerChar = $_; If(((Get-Random -Input @(1..2))-1 -eq 0)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $RandomDelimiters += $UpperLowerChar}
    
    # Only use a subset of current delimiters to randomize what you see in every iteration of this script's output.
    $RandomDelimiters = (Get-Random -Input $RandomDelimiters -Count ($RandomDelimiters.Count/4))

    # Convert $ScriptString to delimited Binary values in [Char] array separated by random delimiter from defined list $RandomDelimiters.
    $DelimitedEncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + (Get-Random -Input $RandomDelimiters))}

    # Remove trailing delimiter from $DelimitedEncodedArray.
    $DelimitedEncodedArray = $DelimitedEncodedArray.SubString(0,$DelimitedEncodedArray.Length-1)

    # Create printable version of $RandomDelimiters in random order to be used by final command.
    $RandomDelimitersToPrint = (Get-Random -Input $RandomDelimiters -Count $RandomDelimiters.Length) -Join ''

    # Generate random case versions for necessary operations.
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StrJoin       = ([Char[]]'[String]::Join'      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'                | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ToInt16       = ([Char[]]'[Convert]::ToInt16(' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''

    # Create printable version of $RandomDelimiters in random order to be used by final command specifically for -Split syntax.
    $RandomDelimitersToPrintForDashSplit = ''
    ForEach($RandomDelimiter in $RandomDelimiters)
    {
        # Random case 'split' string.
        $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''

        $RandomDelimitersToPrintForDashSplit += ('-' + $Split + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1)))
    }
    $RandomDelimitersToPrintForDashSplit = $RandomDelimitersToPrintForDashSplit.Trim()
    
    # Randomly select between various conversion syntax options.
    $RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')'
    $RandomConversionSyntax += $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]"
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)

    # Create array syntax for encoded $ScriptString as alternative to .Split/-Split syntax.
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {
        # Encapsulate current item with single quote if it contains a non-integer.
        If([Convert]::ToString(([Int][Char]$_),$EncodingBase).Trim('0123456789').Length -gt 0) {$Quote = "'"}
        Else {$Quote = ''}
        $EncodedArray += ($Quote + [Convert]::ToString(([Int][Char]$_),$EncodingBase) + $Quote + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))
    }

    # Remove trailing comma from $EncodedArray.
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exists then we could use even more syntax: $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info: https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)

    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)

    # Randomize case of $SetOfsVar and $SetOfsVarBack.
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''

    # Generate the code that will decrypt and execute the payload and randomly select one.
    $BaseScriptArray  = @()
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'." + $Split + "(" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimitersToPrint + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'" + ' '*(Get-Random -Input @(0,1)) + $RandomDelimitersToPrintForDashSplit + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    
    # Generate random JOIN syntax for all above options.
    $NewScriptArray   = @()
    $NewScriptArray  += (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray  += $Join + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray)
    $NewScriptArray  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'

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
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:Public[13]+`$env:Public[5]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"

    # Randomly choose from above invoke operation syntaxes.
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)

    # Randomize the case of selected invoke operation.
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    
    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
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