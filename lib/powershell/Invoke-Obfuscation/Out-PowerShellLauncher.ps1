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



Function Out-PowerShellLauncher
{
<#
.SYNOPSIS

Applies launch syntax to PowerShell command so it can be run from cmd.exe and have its command line arguments further obfuscated via launch obfuscation techniques.

Invoke-Obfuscation Function: Out-PowerShellLauncher
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ObfuscatedTokenCommand, Out-EncapsulatedInvokeExpression (used for WMIC launcher -- located in Out-ObfuscatedStringCommand.ps1), Out-ConcatenatedString (used for WMIC and MSHTA launchers -- located in Out-ObfuscatedTokenCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-PowerShellLauncher obfuscates a given PowerShell command (via stdin, process-level environment variables, clipboard, etc.) while wrapping it in syntax to be launched directly from cmd.exe. Some techniques also push command line arguments to powershell.exe's parent (denoted with +) or even grandparent (denoted with ++) process command line arguments.
1 --> PS
2 --> CMD
3 --> WMIC
4 --> RUNDLL
5 --> VAR+
6 --> STDIN+
7 --> CLIP+
8 --> VAR++
9 --> STDIN++
10 --> CLIP++
11 --> RUNDLL++
12 --> MSHTA++

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER LaunchType

Specifies the launch syntax to apply to ScriptBlock.

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

.PARAMETER SwitchesAsString

(Optional) Specifies above PowerShell execution flags per a single string.

.EXAMPLE

C:\PS> Out-PowerShellLauncher -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive 3

C:\windows\SYstEM32\cmd.EXe  /C   "sET   oPUWV=Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green&&   POWErshELl -NOnINt  -noPrOfil   ${eX`eCUti`on`cO`NTeXT}.\"INVO`k`e`coMMANd\".\"INvo`KeS`C`RIPt\"(   (  GET-CHI`Ldit`EM EnV:OPuwV ).\"v`AlUE\"   )"

.NOTES

This cmdlet is an ideal last step after applying other obfuscation cmdlets to your script block or file path contents. Its more advanced obfuscation options are included to show the Blue Team that powershell.exe's command line arguments may not contain any contents of the command itself, but these could be stored in the parent or grandparent process' command line arguments. There are additional techniques to split the command contents cross multiple commands and have the final PowerShell command re-assemble in memory and execute that are not currently included in this version.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet(1,2,3,4,5,6,7,8,9,10,11,12)]
        [Int]
        $LaunchType,

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
        
        [Parameter(Position = 2)]
        [String]
        $SwitchesAsString
    )

    # To capture and output args in a process tree format for the applied launcher syntax.
    $ArgsDefenderWillSee = @()

    # Convert ScriptBlock to a String.
    $ScriptString = [String]$ScriptBlock
    
    # Check and throw warning message if input $ScriptString contains new line characters.
    If($ScriptString.Contains([Char]13+[Char]10))
    {
        Write-Host ""
        Write-Warning "Current script content contains newline characters.`n         Applying a launcher will not work on the command line.`n         Apply ENCODING obfuscation before applying LAUNCHER."
        Start-Sleep 1
        Return $ScriptString
    }

    # $SwitchesAsString argument for passing in flags from user input in Invoke-Obfuscation.
    If($SwitchesAsString.Length -gt 0)
    {
        If(!($SwitchesAsString.Contains('0')))
        {
            $SwitchesAsString = ([Char[]]$SwitchesAsString | Sort-Object -Unique -Descending) -Join ' '
            ForEach($SwitchAsString in $SwitchesAsString.Split(' '))
            {
                Switch($SwitchAsString)
                {
                    '1' {$NoExit          = $TRUE}
                    '2' {$NonInteractive  = $TRUE}
                    '3' {$NoLogo          = $TRUE}
                    '4' {$NoProfile       = $TRUE}
                    '5' {$Command         = $TRUE}
                    '6' {$WindowsStyle    = 'Hidden'}
                    '7' {$ExecutionPolicy = 'Bypass'}
                    '8' {$Wow64           = $TRUE}
                    default {Write-Error "An invalid `$SwitchAsString value ($SwitchAsString) was passed to switch block for Out-PowerShellLauncher"; Exit;}
                }
            }
        }
    }

    # Parse out and escape key characters in particular token types for powershell.exe (in reverse to make indexes simpler for escaping tokens).
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    $CharsToEscape = @('&','|','<','>')
    For($i=$Tokens.Count-1; $i -ge 0; $i--)
    {
        $Token = $Tokens[$i]
        
        # Manually extract token since tokenization will remove certain characters and whitespace which we want to retain.
        $PreTokenStr    = $ScriptString.SubString(0,$Token.Start)
        $ExtractedToken = $ScriptString.SubString($Token.Start,$Token.Length)
        $PostTokenStr   = $ScriptString.SubString($Token.Start+$Token.Length)
        
        # Escape certain characters that will be problematic on the command line for powershell.exe (\) and cmd.exe (^).
        # Single cmd escaping (^) for strings encapsulated by double quotes. For all other tokens apply double layer escaping (^^^).
        If($Token.Type -eq 'String' -AND !($ExtractedToken.StartsWith("'") -AND $ExtractedToken.EndsWith("'")))
        {
            ForEach($Char in $CharsToEscape)
            {
                If($ExtractedToken.Contains($Char)) {$ExtractedToken = $ExtractedToken.Replace($Char,"^$Char")}
            }

            If($ExtractedToken.Contains('\')) {$ExtractedToken = $ExtractedToken.Replace('\','\\')}
            
            If($ExtractedToken.Contains('"')) {$ExtractedToken = '\"' + $ExtractedToken.SubString(1,$ExtractedToken.Length-1-1) + '\"'}
        }
        Else
        {
            # Before adding layered escaping for special characters for cmd.exe, preserve escaping of ^ used NOT as an escape character (like as part of an Empire key).
            If($ExtractedToken.Contains('^'))
            {
                $ExtractedTokenSplit = $ExtractedToken.Split('^')
                $ExtractedToken = ''
                For($j=0; $j -lt $ExtractedTokenSplit.Count; $j++)
                {
                    $ExtractedToken += $ExtractedTokenSplit[$j]
                    $FirstCharFollowingCaret = $ExtractedTokenSplit[$j+1]
                    If(!$FirstCharFollowingCaret -OR ($CharsToEscape -NotContains $FirstCharFollowingCaret.SubString(0,1)) -AND ($j -ne $ExtractedTokenSplit.Count-1))
                    {
                        $ExtractedToken += '^^^^'
                    }
                }
            }

            ForEach($Char in $CharsToEscape)
            {
                If($ExtractedToken.Contains($Char)) {$ExtractedToken = $ExtractedToken.Replace($Char,"^^^$Char")}
            }
        }
        
        # Add $ExtractedToken back into context in $ScriptString
        $ScriptString = $PreTokenStr + $ExtractedToken + $PostTokenStr
    }
 
    # Randomly select PowerShell execution flag argument substrings and randomize the order for all flags passed to this function.
    # This is to prevent the Blue Team from placing false hope in simple signatures for the shortest form of these arguments or consistent ordering.
    $PowerShellFlags = New-Object String[](0)
    If($PSBoundParameters['NoExit'] -OR $NoExit)
    {
        $FullArgument = "-NoExit"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['NoProfile'] -OR $NoProfile)
    {
        $FullArgument = "-NoProfile"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['NonInteractive'] -OR $NonInteractive)
    {
        $FullArgument = "-NonInteractive"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['NoLogo'] -OR $NoLogo)
    {
        $FullArgument = "-NoLogo"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
    {
        $FullArgument = "-WindowStyle"
        If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
        Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}

        # Randomly decide to overwrite the WindowStyle value with the corresponding integer representation of the predefined parameter value.
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

    # Randomize the order of the command-line arguments.
    # This is to prevent the Blue Team from placing false hope in simple signatures for consistent ordering of these arguments.
    If($PowerShellFlags.Count -gt 1)
    {
        $PowerShellFlags = Get-Random -InputObject $PowerShellFlags -Count $PowerShellFlags.Count
    }

    # If selected then the -Command flag needs to be added last.
    If($PSBoundParameters['Command'] -OR $Command)
    {
        $FullArgument = "-Command"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
    }

    # Randomize the case of all command-line arguments.
    For($i=0; $i -lt $PowerShellFlags.Count; $i++)
    {
        $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    }

    # Insert random-length whitespace between all command-line arguments.
    # Maintain array of PS flags for some launch types (namely CLIP+, CLIP++ and RunDll32).
    $PowerShellFlagsArray = $PowerShellFlags
    $PowerShellFlags = ($PowerShellFlags | ForEach-Object {$_ + ' '*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
    $PowerShellFlags = ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3)

    # Build out paths to binaries depending if 32-bit or 64-bit options were selected.    
    $WinPath      = "C:\WINDOWS"
    $System32Path = "C:\WINDOWS\system32"
    $PathToRunDll = Get-Random -Input @("$System32Path\rundll32"  , "$System32Path\rundll32.exe"  , "rundll32" , "rundll32.exe")
    $PathToMshta  = Get-Random -Input @("$System32Path\mshta"     , "$System32Path\mshta.exe"     , "mshta"    , "mshta.exe")
    $PathToCmd    = Get-Random -Input @("$System32Path\cmd"       , "$System32Path\cmd.exe"       , "cmd.exe"  , "cmd")
    $PathToClip   = Get-Random -Input @("$System32Path\clip"      , "$System32Path\clip.exe"      , "clip"     , "clip.exe")
    $PathToWmic   = Get-Random -Input @("$System32Path\WBEM\wmic" , "$System32Path\WBEM\wmic.exe" , "wmic"     , "wmic.exe")
    
    # If you use cmd or cmd.exe instead of the pathed version, then you don't need to put a whitespace between cmd and and cmd flags. E.g. cmd/c or cmd.exe/c.
    If($PathToCmd.Contains('\'))
    {
        $PathToCmd = $PathToCmd + ' '*(Get-Random -Minimum 2 -Maximum 4)
    }
    Else
    {
        $PathToCmd = $PathToCmd + ' '*(Get-Random -Minimum 0 -Maximum 4)
    }

    If($PSBoundParameters['Wow64'] -OR $Wow64)
    {
        $PathToPowerShell = "$WinPath\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    }
    Else
    {
        # Obfuscation isn't about saving space, and there are reasons you'd potentially want to fully path powershell.exe (more info on this soon).
        #$PathToPowerShell = "$($Env:windir)\System32\WindowsPowerShell\v1.0\powershell.exe"
        $PathToPowerShell = "powershell"
    }

    # Randomize the case of the following variables.
    $PowerShellFlags  = ([Char[]]$PowerShellFlags.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToPowerShell = ([Char[]]$PathToPowerShell.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToRunDll     = ([Char[]]$PathToRunDll.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToMshta      = ([Char[]]$PathToMshta.ToLower()      | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToCmd        = ([Char[]]$PathToCmd.ToLower()        | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToClip       = ([Char[]]$PathToClip.ToLower()       | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToWmic       = ([Char[]]$PathToWmic.ToLower()       | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $SlashC           = ([Char[]]'/c'.ToLower()              | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $Echo             = ([Char[]]'echo'.ToLower()            | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

    # Show warning if an uneven number of double-quotes exists for any $LaunchType.
    $NumberOfDoubleQuotes = $ScriptString.Length-$ScriptString.Replace('"','').Length
    If($NumberOfDoubleQuotes%2 -eq 1)
    {
        Write-Host ""
        Write-Warning "This command contains an unbalanced number of double quotes ($NumberOfDoubleQuotes).`n         Try applying STRING or ENCODING obfuscation options first to encode the double quotes.`n"
        Start-Sleep 1
        Return $ScriptString
    }

    # If no $LaunchType is specified then randomly choose from options 3-20.
    If($LaunchType -eq 0)
    {
        $LaunchType = Get-Random -Input @(3..12)
    }

    # Select launcher syntax.
    Switch($LaunchType)
    {
        1 {
              ########
              ## PS ##
              ########

              # Undo some escaping from beginning of function.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char",$Char)}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + '"' + $ScriptString + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax)

              $CmdLineOutput = $PathToPowerShell + $PSCmdSyntax
          }
        2 {
              #########
              ## CMD ##
              #########

              # Undo some escaping from beginning of function.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char",$Char)}
                  If($ScriptString.Contains("^$Char")) {$ScriptString = $ScriptString.Replace("^$Char","^^^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + '"' + $ScriptString + '"'
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToPowerShell + $PSCmdSyntax
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax)

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        3 {
              ##########
              ## WMIC ##
              ##########

              # WMIC errors when variables contain more than 2 adjacent whitespaces in variable names. Thus we are escaping them here.
              For($i=1; $i -le 12; $i++)
              {
                  $StringToReplace = '${' + ' '*$i + '}'
                  If($ScriptString.Contains($StringToReplace))
                  {
                      $ScriptString = $ScriptString.Replace($StringToReplace,$StringToReplace.Replace(' ','\ '))
                  }
              }

              # Undo escaping from beginning of function. $CharsToEscape is defined at beginning of this function.
              ForEach($Char in $CharsToEscape)
              {
                  While($ScriptString.Contains('^' + $Char))
                  {
                      $ScriptString = $ScriptString.Replace(('^' + $Char),$Char)
                  }
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }

              # Perform inline substitutions to remove commas from command line for wmic.exe.
              If($ScriptString.Contains(','))
              {
                  # SetVariables will only be used if more than 5 double quotes or more than 5 commas need to be escaped.
                  $SetVariables = ''

                  # Since we are converting the PowerShell command into strings for concatenation we need to escape and double-escape $ for proper variable interpretation by PowerShell.
                  If($ScriptString.Contains('$'))
                  {
                      $ScriptString = $ScriptString.Replace('$','`$')
                         
                      # Double escape any $ characters that were already escaped prior to above escaping step.
                      If($ScriptString.Contains('``$'))
                      {
                          $ScriptString = $ScriptString.Replace('``$','```$')
                      }
                  }

                  # Double escape any escaped " characters.
                  If($ScriptString.Contains('`"'))
                  {
                      $ScriptString = $ScriptString.Replace('`"','``"')
                  }

                  # Substitute double quotes as well if we're substituting commas as this requires treating the entire command as a string by encapsulating it with double quotes.
                  If($ScriptString.Contains('"'))
                  {
                      # Remove all layers of escaping for double quotes as they are no longer necessary since we're casting these double quotes to ASCII values.
                      While($ScriptString.Contains('\"'))
                      {
                          $ScriptString = $ScriptString.Replace('\"','"')
                      }

                      # Randomly select a syntax for the Char conversion of a double quote ASCII value and then ramdomize the case.
                      $CharCastDoubleQuote = ([Char[]](Get-Random -Input @('[String][Char]34','([Char]34).ToString()')) | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
                      If($ScriptString.Length-$ScriptString.Replace('"','').Length -le 5)
                      {
                          # Replace double quote(s) with randomly selected ASCII value conversion representation -- inline concatenation.
                          $SubstitutionSyntax  = ('\"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $CharCastDoubleQuote + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '\"')
                          $ScriptString        = $ScriptString.Replace('"',$SubstitutionSyntax).Replace('\"\"+','').Replace('\"\" +','').Replace('\"\"  +','').Replace('\"\"   +','')
                      }
                      Else
                      {
                          # Characters we will use to generate random variable names.
                          # For simplicity do NOT include single- or double-quotes in this array.
                          $CharsToRandomVarName  = @(0..9)
                          $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')

                          # Randomly choose variable name starting length.
                          $RandomVarLength = (Get-Random -Input @(1..2))
   
                          # Create random variable with characters from $CharsToRandomVarName.
                          If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
                          $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')

                          # Keep generating random variables until we find one that is not a substring of $ScriptString.
                          While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
                          {
                              $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
                              $RandomVarLength++
                          }

                          # Randomly decide if the variable name will be concatenated inline or not.
                          $RandomVarNameMaybeConcatenated = $RandomVarName
                          If((Get-Random -Input @(0..1)) -eq 0)
                          {
                              $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName "'") + ')'
                          }

                          # Generate random variable SET syntax.
                          $RandomVarSetSyntax  = @()
                          $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $CharCastDoubleQuote
                          $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $CharCastDoubleQuote + ' '*(Get-Random @(0..2)) + ')'
    
                          # Randomly choose from above variable syntaxes.
                          $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)

                          # Replace double quotes with randomly selected ASCII value conversion representation -- variable replacement to save space for high counts of double quotes to substitute.
                          $SetVariables += $RandomVarSet + ' '*(Get-Random @(1..2)) + ';'
                          $ScriptString = $ScriptString.Replace('"',"`${$RandomVarName}")
                      }
                  }
                  
                  # Randomly select a syntax for the Char conversion of a comma ASCII value and then ramdomize the case.
                  $CharCastComma= ([Char[]](Get-Random -Input @('[String][Char]44','([Char]44).ToString()')) | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
                  If($ScriptString.Length-$ScriptString.Replace(',','').Length -le 5)
                  {
                      # Replace commas with randomly selected ASCII value conversion representation -- inline concatenation.
                      $SubstitutionSyntax  = ('\"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $CharCastComma + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '\"')
                      $ScriptString        = $ScriptString.Replace(',',$SubstitutionSyntax).Replace('\"\"+','').Replace('\"\" +','').Replace('\"\"  +','').Replace('\"\"   +','')
                  }
                  Else
                  {
                      # Characters we will use to generate random variable names.
                      # For simplicity do NOT include single- or double-quotes in this array.
                      $CharsToRandomVarName  = @(0..9)
                      $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')

                      # Randomly choose variable name starting length.
                      $RandomVarLength = (Get-Random -Input @(1..2))
   
                      # Create random variable with characters from $CharsToRandomVarName.
                      If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
                      $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')

                      # Keep generating random variables until we find one that is not a substring of $ScriptString.
                      While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
                      {
                          $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
                          $RandomVarLength++
                      }

                      # Randomly decide if the variable name will be concatenated inline or not.
                      $RandomVarNameMaybeConcatenated = $RandomVarName
                      If((Get-Random -Input @(0..1)) -eq 0)
                      {
                          $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName "'") + ')'
                      }

                      # Generate random variable SET syntax.
                      $RandomVarSetSyntax  = @()
                      $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $CharCastComma
                      $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $CharCastComma + ' '*(Get-Random @(0..2)) + ')'

                      # Randomly choose from above variable syntaxes.
                      $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)

                      # Replace commas with randomly selected ASCII value conversion representation -- variable replacement to save space for high counts of commas to substitute.
                      $SetVariables += $RandomVarSet + ' '*(Get-Random @(1..2)) + ';'
                      $ScriptString = $ScriptString.Replace(',',"`${$RandomVarName}")
                  }

                  # Encapsulate entire command with escaped double quotes since entire command is now an inline concatenated string to support the above character substitution(s).
                  $ScriptString =  '\"' + $ScriptString + '\"'

                  # Randomly decide on invoke operation since we've applied an additional layer of string manipulation in above steps.
                  # Keep running Out-EncapsulatedInvokeExpression until we get a syntax that does NOT contain commas.
                  # Examples like .((gv '*mdR*').Name[3,11,2]-Join'') can have their commas escaped like in above step. However, wmic.exe errors with opening [ without a closing ] in the string literal.
                  $ScriptStringTemp = ','
                  While($ScriptStringTemp.Contains(','))
                  {
                      $ScriptStringTemp = Out-EncapsulatedInvokeExpression $ScriptString
                  }

                  # Now that we have an invocation syntax that does not contain commas we will set $ScriptStringTemp's results back into $ScriptString.
                  $ScriptString = $ScriptStringTemp

                  # Prepend with $SetVariables (which will be blank if no variables were set in above sustitution logic depending on the number of double quotes and commas that need to be replaced.
                  $ScriptString = $SetVariables + $ScriptString
              }

              # Generate random case syntax for PROCESS CALL CREATE arguments for WMIC.exe.
              $WmicArguments = ([Char[]]'process call create' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Randomize the whitespace between each element of $WmicArguments which randomly deciding between encapsulating each argument with single quotes, double quotes or no quote.
              $WmicArguments = (($WmicArguments.Split(' ') | ForEach-Object {$RandomQuotes = (Get-Random -Input @('"',"'",' ')); $RandomQuotes + $_ + $RandomQuotes + ' '*(Get-Random -Minimum 1 -Maximum 4)}) -Join '').Trim()

              # Pair escaped double quotes with a prepended additional double quote so that wmic.exe does not treat the string as a separate argument for wmic.exe but the double quote still exists for powershell.exe's functionality.
              If($ScriptString.Contains('\"'))
              {
                  $ScriptString = $ScriptString.Replace('\"','"\"')
              }

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax   = $PowerShellFlags + $ScriptString
              $WmicCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $WmicArguments + ' '*(Get-Random -Minimum 1 -Maximum 4) + '"' + $PathToPowerShell + $PSCmdSyntax + '"'
    
              # Set argument info for process tree output after this Switch block.
              # Even though wmic.exe will show in command line arguments, it will not be the parent process of powershell.exe. Instead, the already-existing instance of WmiPrvSE.exe will spawn powershell.exe.
              $ArgsDefenderWillSee += , @("[Unrelated to WMIC.EXE execution] C:\WINDOWS\system32\wbem\wmiprvse.exe", " -secured -Embedding")
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax)

              $CmdLineOutput = $PathToWmic + $WmicCmdSyntax
          }
        4 {
              ############
              ## RUNDLL ##
              ############

              # Shout out and big thanks to Matt Graeber (@mattifestation) for pointing out this method of executing any binary directly from rundll32.exe.

              # Undo escaping from beginning of function.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }

              # Generate random case syntax for SHELL32.DLL argument for RunDll32.exe.
              $Shell32Dll = ([Char[]]'SHELL32.DLL' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Put the execution flags in the format required by rundll32.exe: each argument separately encapusulated in double quotes.
              $ExecutionFlagsRunDllSyntax = ($PowerShellFlagsArray | Where-Object {$_.Trim().Length -gt 0} | ForEach-Object {'"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $_ + ' '*(Get-Random -Minimum 0 -Maximum 3) + '"' + ' '*(Get-Random -Minimum 1 -Maximum 4)}) -Join ''
 
              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax     = ' '*(Get-Random -Minimum 1 -Maximum 4) + $ExecutionFlagsRunDllSyntax + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$ScriptString`""
              $RunDllCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $Shell32Dll + (Get-Random -Input @(',',' ', ((Get-Random -Input @(',',',',',',' ',' ',' ') -Count (Get-Random -Input @(4..6)))-Join''))) + 'ShellExec_RunDLL' + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$PathToPowerShell`"" + $PSCmdSyntax
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToRunDll          , $RunDllCmdSyntax)
              $ArgsDefenderWillSee += , @("`"$PathToPowerShell`"", $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToRunDll + $RunDllCmdSyntax
          }
        5 {
              ##########
              ## VAR+ ##
              ##########

              # Undo some escaping from beginning of function.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }
                        
              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}

              # Choose random syntax for invoking command stored in process-level environment variable.
              # Generate random variable name to store the $ScriptString command.
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Generate random syntax for invoking process-level environment variable syntax.
              $InvokeVariableSyntax = Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName

              # Generate random case syntax for setting the above random variable name.
              $SetSyntax = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='

              # Randomize the case of the following variables.
              $SetSyntax = ([Char[]]$SetSyntax.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + $InvokeVariableSyntax
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToPowerShell + $PSCmdSyntax + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        6 {
              ############
              ## STDIN+ ##
              ############

              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
             
              # Choose random syntax for invoking powershell.exe's StdIn.
              $PowerShellStdin = Out-RandomPowerShellStdInInvokeSyntax
              
              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + $PowerShellStdin
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"'  + ' '*(Get-Random -Minimum 0 -Maximum 3) + $Echo + (Get-Random -Input ('/','\',' '*(Get-Random -Minimum 1 -Maximum 3))) + $ScriptString + ' '*(Get-Random -Minimum 1 -Maximum 3) + '|' + ' '*(Get-Random -Minimum 1 -Maximum 3) + $PathToPowerShell + $PSCmdSyntax + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        7 {
              ###########
              ## CLIP+ ##
              ###########

              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
             
              # Choose random syntax for invoking powershell.exe's StdIn.
              $PowerShellClip = Out-RandomClipboardInvokeSyntax

              # If this launcher is run in PowerShell 2.0 then Single-Threaded Apartment must be specified with -st or -sta.
              # Otherwise you will get the following error: "Current thread must be set to single thread apartment (STA) mode before OLE calls can be made."
              # Since Invoke-Obfuscation output is designed to run on any PowerShell version then for this launcher we will add the -st/-sta flag to $PowerShellFlags.
              
              # If selected then the -Command flag needs to remain last (where it currently is).
              $CommandFlagValue = $NULL
              If($PSBoundParameters['Command'] -OR $Command)
              {
                  $UpperLimit = $PowerShellFlagsArray.Count-1
                  $CommandFlagValue = $PowerShellFlagsArray[$PowerShellFlagsArray.Count-1]
              }
              Else
              {
                  $UpperLimit = $PowerShellFlagsArray.Count
              }

              # Re-extract PowerShellFlags so we can add in -st/-sta and then reorder (maintaining command flag at the end if present).
              $PowerShellFlags = @()
              For($i=0; $i -lt $UpperLimit; $i++)
              {
                  $PowerShellFlags += $PowerShellFlagsArray[$i]
              }

              # Add in -st/-sta to PowerShellFlags.
              $PowerShellFlags += (Get-Random -Input @('-st','-sta'))
              
              # Randomize the order of the command-line arguments.
              # This is to prevent the Blue Team from placing false hope in simple signatures for consistent ordering of these arguments.
              If($PowerShellFlags.Count -gt 1)
              {
                  $PowerShellFlags = Get-Random -InputObject $PowerShellFlags -Count $PowerShellFlags.Count
              }

              # If selected then the -Command flag needs to be added last.
              If($CommandFlagValue)
              {
                  $PowerShellFlags += $CommandFlagValue
              }

              # Randomize the case of all command-line arguments.
              For($i=0; $i -lt $PowerShellFlags.Count; $i++)
              {
                  $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
              }

              # Insert random-length whitespace between all command-line arguments.
              $PowerShellFlags = ($PowerShellFlags | ForEach-Object {$_ + ' '*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
              $PowerShellFlags = ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3)

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + $PowerShellClip
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"'  + ' '*(Get-Random -Minimum 0 -Maximum 3) + $Echo + (Get-Random -Input ('/','\',' '*(Get-Random -Minimum 1 -Maximum 3))) + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 2) + '|' + ' '*(Get-Random -Minimum 0 -Maximum 2) + $PathToClip + ' '*(Get-Random -Minimum 0 -Maximum 2) + '&&' + ' '*(Get-Random -Minimum 1 -Maximum 3) + $PathToPowerShell + $PSCmdSyntax + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        8 {
              ###########
              ## VAR++ ##
              ###########

              # Undo some escaping from beginning of function.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }

              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              
              # Choose random syntax for invoking command stored in process-level environment variable.
              # Generate random variable names to store the $ScriptString command and PowerShell syntax.
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2 = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName2 = ([Char[]]$VariableName2.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Generate random case syntax for setting the above random variable names.
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax2 = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2 = $SetSyntax2 + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName2 + '='

              # Randomize the case of the following variables.
              $SetSyntax     = ([Char[]]$SetSyntax.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2    = ([Char[]]$SetSyntax2.ToLower()    | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2 = ([Char[]]$VariableName2.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    
              # Generate random syntax for invoking process-level environment variable syntax.
              $InvokeOption = Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName

              # Add additional escaping for vertical pipe (and other characters defined below) if necessary since this is going inside an environment variable for the final $CmdLineOutput set below.
              ForEach($Char in @('<','>','|','&'))
              {
                  If($InvokeOption.Contains("^$Char"))
                  {
                      $InvokeOption = $InvokeOption.Replace("^$Char","^^^$Char")
                  }
              }

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3) + $InvokeOption
              $CmdSyntax2  = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 2) + "%$VariableName2%"
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + $SetSyntax2 + $PathToPowerShell + $PSCmdSyntax + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToCmd + $CmdSyntax2 + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax2)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        9 {
              #############
              ## STDIN++ ##
              #############
              
              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              
              # Choose random syntax for invoking command stored in process-level environment variable.
              # Generate random variable names to store the $ScriptString command and PowerShell syntax.
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2 = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName2 = ([Char[]]$VariableName2.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Generate random case syntax for setting the above random variable names.
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax2 = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2 = $SetSyntax2 + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName2 + '='

              # Generate numerous ways to invoke with $ExecutionContext as a variable, including Get-Variable varname, Get-ChildItem Variable:varname, Get-Item Variable:varname, etc.
              $ExecContextVariable  = @()
              $ExecContextVariable += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + 'variable:' + (Get-Random -Input @('Ex*xt','E*t','*xec*t','*ecu*t','*cut*t','*cuti*t','*uti*t','E*ext','E*xt','E*Cont*','E*onte*','E*tex*','ExecutionContext')) + ').Value'
              # Select random option from above.
              $ExecContextVariable = Get-Random -Input $ExecContextVariable

              # Generate numerous ways to invoke command stored in environment variable.
              $GetRandomVariableSyntax  = @()
              $GetRandomVariableSyntax += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + 'env:' + $VariableName + ').Value'
              $GetRandomVariableSyntax += ('(' + '[Environment]::GetEnvironmentVariable(' + "'$VariableName'" + ',' + "'Process'" + ')' + ')')
              # Select random option from above.
              $GetRandomVariableSyntax = Get-Random -Input $GetRandomVariableSyntax

              # Generate random Invoke-Expression/IEX/$ExecutionContext syntax.
              $InvokeOptions  = @()
              $InvokeOptions += (Get-Random -Input ('IEX','Invoke-Expression')) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $GetRandomVariableSyntax
              $InvokeOptions += (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $GetRandomVariableSyntax + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
              # Select random option from above.
              $InvokeOption = Get-Random -Input $InvokeOptions

              # Randomize the case of the following variables.
              $SetSyntax            = ([Char[]]$SetSyntax.ToLower()            | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2           = ([Char[]]$SetSyntax2.ToLower()           | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName         = ([Char[]]$VariableName.ToLower()         | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2        = ([Char[]]$VariableName2.ToLower()        | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeOption         = ([Char[]]$InvokeOption.ToLower()         | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $ExecContextVariable  = ([Char[]]$ExecContextVariable.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $GetRandomVariableSyntax = ([Char[]]$GetRandomVariableSyntax.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Generate random syntax for invoking process-level environment variable syntax.
              $InvokeVariableSyntax = Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName

              # Choose random syntax for invoking powershell.exe's StdIn.
              $PowerShellStdin = Out-RandomPowerShellStdInInvokeSyntax
              
              # Undo some escaping from beginning of function.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
    
                  If($PowerShellStdin.Contains("^$Char")) {$PowerShellStdin = $PowerShellStdin.Replace("^$Char","^^^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellStdin + ' '*(Get-Random -Minimum 0 -Maximum 3)
              $CmdSyntax2  = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 2) + "%$VariableName2%"
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + ' '*(Get-Random -Minimum 0 -Maximum 3)+ $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 3) + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $SetSyntax2 + $Echo + ' '*(Get-Random -Minimum 1 -Maximum 3) + $InvokeOption + ' '*(Get-Random -Minimum 0 -Maximum 3) + '^|' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $PathToPowerShell + $PSCmdSyntax + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $PathToCmd + $CmdSyntax2 + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax2)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        10 {
              ############
              ## CLIP++ ##
              ############

              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
             
              # Choose random syntax for invoking powershell.exe's StdIn.
              $PowerShellClip = Out-RandomClipboardInvokeSyntax

              # Since we're embedding $PowerShellClip syntax one more process deep we need to double-escape & < > and | characters for cmd.exe.
              ForEach($Char in @('<','>','|','&'))
              {
                  # Remove single escaping and then escape all characters. This will handle single-escaped and not-escaped characters.
                  If($PowerShellClip.Contains("^$Char")) 
                  {
                      $PowerShellClip = $PowerShellClip.Replace("^$Char","^^^$Char")
                  }
              }

              # If this launcher is run in PowerShell 2.0 then Single-Threaded Apartment must be specified with -st or -sta.
              # Otherwise you will get the following error: "Current thread must be set to single thread apartment (STA) mode before OLE calls can be made."
              # Since Invoke-Obfuscation output is designed to run on any PowerShell version then for this launcher we will add the -st/-sta flag to $PowerShellFlags.
              
              # If selected then the -Command flag needs to remain last (where it currently is).
              $CommandFlagValue = $NULL
              If($PSBoundParameters['Command'] -OR $Command)
              {
                  $UpperLimit = $PowerShellFlagsArray.Count-1
                  $CommandFlagValue = $PowerShellFlagsArray[$PowerShellFlagsArray.Count-1]
              }
              Else
              {
                  $UpperLimit = $PowerShellFlagsArray.Count
              }

              # Re-extract PowerShellFlags so we can add in -st/-sta and then reorder (maintaining command flag at the end if present).
              $PowerShellFlags = @()
              For($i=0; $i -lt $UpperLimit; $i++)
              {
                  $PowerShellFlags += $PowerShellFlagsArray[$i]
              }

              # Add in -st/-sta to PowerShellFlags.
              $PowerShellFlags += (Get-Random -Input @('-st','-sta'))
              
              # Randomize the order of the command-line arguments.
              # This is to prevent the Blue Team from placing false hope in simple signatures for consistent ordering of these arguments.
              If($PowerShellFlags.Count -gt 1)
              {
                  $PowerShellFlags = Get-Random -InputObject $PowerShellFlags -Count $PowerShellFlags.Count
              }

              # If selected then the -Command flag needs to be added last.
              If($CommandFlagValue)
              {
                  $PowerShellFlags += $CommandFlagValue
              }

              # Randomize the case of all command-line arguments.
              For($i=0; $i -lt $PowerShellFlags.Count; $i++)
              {
                  $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
              }

              # Insert random-length whitespace between all command-line arguments.
              $PowerShellFlags = ($PowerShellFlags | ForEach-Object {$_ + ' '*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
              $PowerShellFlags = ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3)

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax = $PowerShellFlags + $PowerShellClip
              $CmdSyntax2  = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToPowerShell + $PsCmdSyntax
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"'  + ' '*(Get-Random -Minimum 0 -Maximum 3) + $Echo + (Get-Random -Input ('/','\',' '*(Get-Random -Minimum 1 -Maximum 3))) + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 2) + '|' + ' '*(Get-Random -Minimum 0 -Maximum 2) + $PathToClip + ' '*(Get-Random -Minimum 0 -Maximum 2) + '&&' + $PathToCmd + $CmdSyntax2 + '"'
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax2)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        11 {
              ##############
              ## RUNDLL++ ##
              ##############

              # Shout out and big thanks to Matt Graeber (@mattifestation) for pointing out this method of executing any binary directly from rundll32.exe.

              # Undo one layer of escaping from beginning of function since we're only dealing with one level of cmd.exe escaping in this block.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }

              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              
              # Choose random syntax for invoking command stored in process-level environment variable.
              # Generate random variable names to store the $ScriptString command and PowerShell syntax.
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              
              # Generate random case syntax for setting the above random variable names.
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              
              # Randomize the case of the following variables.
              $SetSyntax     = ([Char[]]$SetSyntax.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              
              # Generate random syntax for invoking process-level environment variable syntax.
              $InvokeOption = (Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName).Replace('\"',"'").Replace('`','')

              # Generate random case syntax for SHELL32.DLL argument for RunDll32.exe.
              $Shell32Dll = ([Char[]]'SHELL32.DLL' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

              # Put the execution flags in the format required by rundll32.exe: each argument separately encapusulated in double quotes.
              $ExecutionFlagsRunDllSyntax = ($PowerShellFlagsArray | Where-Object {$_.Trim().Length -gt 0} | ForEach-Object {'"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $_ + ' '*(Get-Random -Minimum 0 -Maximum 3) + '"' + ' '*(Get-Random -Minimum 1 -Maximum 4)}) -Join ''
 
              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax     = ' '*(Get-Random -Minimum 1 -Maximum 4) + $ExecutionFlagsRunDllSyntax + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$InvokeOption`""
              $RundllCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $Shell32Dll + (Get-Random -Input @(',',' ', ((Get-Random -Input @(',',',',',',' ',' ',' ') -Count (Get-Random -Input @(4..6)))-Join''))) + 'ShellExec_RunDLL' + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$PathToPowerShell`"" + $PSCmdSyntax
              $CmdSyntax       = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + $PathToRunDll + $RundllCmdSyntax
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd             , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToRunDll          , $RundllCmdSyntax)
              $ArgsDefenderWillSee += , @("`"$PathToPowerShell`"", $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
        }
        12 {
              #############
              ## MSHTA++ ##
              #############

              # Undo one layer of escaping from beginning of function since we're only dealing with one level of cmd.exe escaping in this block.
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }

              # Switch cmd.exe escape with powershell.exe escape of double-quote.
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              
              # Choose random syntax for invoking command stored in process-level environment variable.
              # Generate random variable names to store the $ScriptString command and PowerShell syntax.
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              
              # Generate random case syntax for setting the above random variable names.
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              
              # Randomize the case of the following variables.
              $SetSyntax     = ([Char[]]$SetSyntax.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              
              # Generate random syntax for invoking process-level environment variable syntax.
              # Keep calling Out-RandomInvokeRandomEnvironmentVariableSyntax until we get the shorter syntax (not using $ExecutionContext syntax) since mshta.exe has a short argument size limitation.
              $InvokeOption = (Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName).Replace('\"',"'").Replace('`','')
              While($InvokeOption.Length -gt 200)
              {
                  $InvokeOption = (Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName).Replace('\"',"'").Replace('`','')
              }

              # Generate randomize case syntax for all available command arguments for mshta.exe.
              $CreateObject = ([Char[]]'VBScript:CreateObject' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $WScriptShell = ([Char[]]'WScript.Shell'         | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $Run          = ([Char[]]'.Run'                  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $TrueString   = ([Char[]]'True'                  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $WindowClose  = ([Char[]]'Window.Close'          | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
            
              # Randomly decide whether to concatenate WScript.Shell or just encapsulate it with double quotes.
              If((Get-Random -Input @(0..1)) -eq 0)
              {
                  $WScriptShell = Out-ConcatenatedString $WScriptShell '"'
              }
              Else
              {
                  $WScriptShell = '"' + $WScriptShell + '"'
              }

              # Randomly decide whether or not to concatenate PowerShell command.
              If((Get-Random -Input @(0..1)) -eq 0)
              {
                  # Concatenate $InvokeOption and unescape double quotes from the result.
                  $SubStringArray += (Out-ConcatenatedString $InvokeOption.Trim('"') '"').Replace('`"','"')

                  # Remove concatenation introduced in above step if it concatenates immediately after a cmd.exe escape character.
                  If($InvokeOption.Contains('^"+"'))
                  {
                      $InvokeOption = $InvokeOption.Replace('^"+"','^')
                  }
              }

              # Random choose between using the numeral 1 and using a random subtraction syntax that is equivalent to 1.
              If((Get-Random -Input @(0..1)) -eq 0)
              {
                  $One = 1
              }
              Else
              {
                  # Randomly select between two digit and three digit subtraction syntax.
                  $RandomNumber = Get-Random -Minimum 3 -Maximum 25
                  If(Get-Random -Input @(0..1))
                  {
                      $One = [String]$RandomNumber + '-' + ($RandomNumber-1)
                  }
                  Else
                  {
                      $SecondRandomNumber = Get-Random -Minimum 1 -Maximum $RandomNumber
                      $One = [String]$RandomNumber + '-' + $SecondRandomNumber + '-' + ($RandomNumber-$SecondRandomNumber-1)
                  }

                  # Randomly decide to encapsulate with parentheses (not necessary).
                  If((Get-Random -Input @(0..1)) -eq 0)
                  {
                      $One = '(' + $One + ')'
                  }
              }

              # Build out command line syntax in reverse so we can display the process argument tree at the end of this Switch block.
              $PSCmdSyntax    = $PowerShellFlags + ' '*(Get-Random -Minimum 0 -Maximum 3) + $InvokeOption + '",' + $One + ',' + $TrueString + ")($WindowClose)"
              $MshtaCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $CreateObject + "($WScriptShell)" + $Run + '("' + $PathToPowerShell + $PSCmdSyntax + '"'
              $CmdSyntax      = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + $PathToMshta + $MshtaCmdSyntax
    
              # Set argument info for process tree output after this Switch block.
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToMshta     , $MshtaCmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))

              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        default {Write-Error "An invalid `$LaunchType value ($LaunchType) was passed to switch block for Out-PowerShellLauncher."; Exit;}
    }

    # Output process tree output format of applied launcher to help the Blue Team find indicators and the Red Team to better avoid detection.
    If($ArgsDefenderWillSee.Count -gt 0)
    {
        Write-Host "`n`nProcess Argument Tree of ObfuscatedCommand with current launcher:"
    
        $Counter = -1
        ForEach($Line in $ArgsDefenderWillSee)
        {
            If($Line.Count -gt 1)
            {
                $Part1 = $Line[0]
                $Part2 = $Line[1]
            }
            Else
            {
                $Part1 = $Line
                $Part2 = ''
            }

            $LineSpacing = ''
            If($Counter -ge 0)
            {
                $LineSpacing = '     '*$Counter
                Write-Host "$LineSpacing|`n$LineSpacing\--> " -NoNewline
            }

            # Print each command and argument, handling if the argument length is too long to display coherently.
            Write-Host $Part1 -NoNewLine -ForegroundColor Yellow

            # Maximum size for cmd.exe and clipboard.
            $CmdMaxLength = 8190

            If($Part2.Length -gt $CmdMaxLength)
            {
                # Output Part2, handling if the size of Part2 exceeds $CmdMaxLength characters.
                $RedactedPrintLength = $CmdMaxLength/5
        
                # Handle printing redaction message in middle of screen. #OCD
                $CmdLineWidth = (Get-Host).UI.RawUI.BufferSize.Width
                $RedactionMessage = "<REDACTED: ArgumentLength = $($Part1.Length + $Part2.Length)>"
                $CenteredRedactionMessageStartIndex = (($CmdLineWidth-$RedactionMessage.Length)/2) - ($Part1.Length+$LineSpacing.Length)
                $CurrentRedactionMessageStartIndex = ($RedactedPrintLength % $CmdLineWidth)
        
                If($CurrentRedactionMessageStartIndex -gt $CenteredRedactionMessageStartIndex)
                {
                    $RedactedPrintLength = $RedactedPrintLength-($CurrentRedactionMessageStartIndex-$CenteredRedactionMessageStartIndex)
                }
                Else
                {
                    $RedactedPrintLength = $RedactedPrintLength+($CenteredRedactionMessageStartIndex-$CurrentRedactionMessageStartIndex)
                }
    
                Write-Host $Part2.SubString(0,$RedactedPrintLength) -NoNewLine -ForegroundColor Cyan
                Write-Host $RedactionMessage -NoNewLine -ForegroundColor Magenta
                Write-Host $Part2.SubString($Part2.Length-$RedactedPrintLength) -ForegroundColor Cyan
            }
            Else
            {
                Write-Host $Part2 -ForegroundColor Cyan
            }

            $Counter++
        }
        Start-Sleep 1
    }

    # Make sure final command doesn't exceed cmd.exe's character limit.
    # Only apply this check to LaunchType values less than 13 since all the other launchers are not command line launchers.
    $CmdMaxLength = 8190
    If(($CmdLineOutput.Length -gt $CmdMaxLength) -AND ($LaunchType -lt 13))
    {
        Write-Host ""
        Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        Start-Sleep 1
    }

    Return $CmdLineOutput
}


Function Out-RandomInvokeRandomEnvironmentVariableSyntax
{
<#
.SYNOPSIS

HELPER FUNCTION :: Generates randomized syntax for invoking a process-level environment variable.

Invoke-Obfuscation Function: Out-RandomInvokeRandomEnvironmentVariableSyntax
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ObfuscatedTokenCommand, Out-EncapsulatedInvokeExpression (found in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomInvokeRandomEnvironmentVariableSyntax generates random invoke syntax and random process-level environment variable retrieval syntax for invoking command contents that are stored in a user-input process-level environment variable. This function is primarily used as a helper function for Out-PowerShellLauncher.

.PARAMETER EnvVarName

User input string or array of strings containing environment variable names to randomly select and apply invoke syntax.

.EXAMPLE

C:\PS> Out-RandomInvokeRandomEnvironmentVariableSyntax 'varname'

.(\"In\"  +\"v\"  +  \"o\"+  \"Ke-ExpRes\"+ \"sION\" ) (^&( \"GC\" +\"i\"  ) eNV:vaRNAMe  ).\"V`ALue\"

.NOTES

This cmdlet is a helper function for Out-PowerShellLauncher's more sophisticated $LaunchType options where the PowerShell command is set in process-level environment variables for command line obfuscation benefits.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $EnvVarName
    )

    # Retrieve random variable from variable name array passed in as argument.
    $EnvVarName = Get-Random -Input $EnvVarName

    # Generate numerous ways to invoke with $ExecutionContext as a variable, including Get-Variable varname, Get-ChildItem Variable:varname, Get-Item Variable:varname, etc.
    $ExecContextVariables  = @()
    $ExecContextVariables += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + "'variable:" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "').Value"
    $ExecContextVariables += '(' + (Get-Random -Input @('Get-Variable','GV','Variable')) + ' ' + "'" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "'" + (Get-Random -Input (').Value',(' ' + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ')')))

    # Select random option from above.
    $ExecContextVariable = Get-Random -Input $ExecContextVariables

    # Generate numerous ways to invoke command stored in environment variable.
    $GetRandomVariableSyntax  = @()
    $GetRandomVariableSyntax += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + 'env:' + $EnvVarName + ').Value'
    $GetRandomVariableSyntax += ('(' + '[Environment]::GetEnvironmentVariable(' + "'$EnvVarName'" + ',' + "'Process'" + ')' + ')')
    
    # Select random option from above.
    $GetRandomVariableSyntax = Get-Random -Input $GetRandomVariableSyntax

    # Generate random invoke operation syntax.
    # 50% split between using $ExecutionContext invocation syntax versus IEX/Invoke-Expression/variable-obfuscated-'iex' syntax generated by Out-EncapsulatedInvokeExpression.
    $ExpressionToInvoke = $GetRandomVariableSyntax
    If(Get-Random -Input @(0..1))
    {
        # Randomly decide on invoke operation since we've applied an additional layer of string manipulation in above steps.
        $InvokeOption = Out-EncapsulatedInvokeExpression $ExpressionToInvoke
    }
    Else
    {
        $InvokeOption = (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ExpressionToInvoke + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
    }

    # Random case of $InvokeOption.
    $InvokeOption = ([Char[]]$InvokeOption.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

    # Run random invoke operation through the appropriate token obfuscators if $PowerShellStdIn is not simply a value of - from above random options.
    If($InvokeOption -ne '-')
    {
        # Run through all available token obfuscation functions in random order.
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption))
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption)) 'RandomWhitespace' 1
    }
    
    # For obfuscated commands generated for $InvokeOption syntax, single-escape & < > and | characters for cmd.exe.
    ForEach($Char in @('<','>','|','&'))
    {
        # Remove single escaping and then escape all characters. This will handle single-escaped and not-escaped characters.
        If($InvokeOption.Contains("$Char")) 
        {
            $InvokeOption = $InvokeOption.Replace("$Char","^$Char")
        }
    }
    
    # Escape double-quote with backslash for powershell.exe.
    If($InvokeOption.Contains('"'))
    {
        $InvokeOption = $InvokeOption.Replace('"','\"')
    }
    
    Return $InvokeOption
}


Function Out-RandomPowerShellStdInInvokeSyntax
{
<#
.SYNOPSIS

HELPER FUNCTION :: Generates randomized PowerShell syntax for invoking a command passed to powershell.exe via standard input.

Invoke-Obfuscation Function: Out-RandomPowerShellStdInInvokeSyntax
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ObfuscatedTokenCommand, Out-EncapsulatedInvokeExpression (found in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomPowerShellStdInInvokeSyntax generates random PowerShell syntax for invoking a command passed to powershell.exe via standard input. This technique is included to show the Blue Team that powershell.exe's command line arguments may not contain any contents of the command itself, but these could be stored in the parent process if passed to powershell.exe via standard input.

.EXAMPLE

C:\PS> Out-RandomPowerShellStdInInvokeSyntax

(  ^& ('v'+( 'aR'+ 'Iabl'  )  + 'E' ) ('exE'+'CUTiOnco'  +'n'+ 'TeX'  + 't' ) -Val).\"INvOKec`oMm`A`ND\".\"invO`K`es`CRiPt\"(${I`N`puT} )

.NOTES

This cmdlet is a helper function for Out-PowerShellLauncher's more sophisticated $LaunchType options where the PowerShell command is passed to powershell.exe via standard input for command line obfuscation benefits.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
    
    # Build out random PowerShell stdin syntax like:
    # | powershell -      <-- default to this if $NoExit flag is defined because this will cause an error for the other options
    # | powershell IEX $Input
    # | powershell $ExecutionContext.InvokeCommand.InvokeScript($Input)
    # Also including numerous ways to invoke with $ExecutionContext as a variable, including Get-Variable varname, Get-ChildItem Variable:varname, Get-Item Variable:varname, etc.
    $ExecContextVariables  = @()
    $ExecContextVariables += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + "'variable:" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "').Value"
    $ExecContextVariables += '(' + (Get-Random -Input @('Get-Variable','GV','Variable')) + ' ' + "'" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "'" + (Get-Random -Input (').Value',(' ' + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ')')))
    # Select random option from above.
    $ExecContextVariable = (Get-Random -Input $ExecContextVariables)

    $RandomInputVariable = (Get-Random -Input @('$Input','${Input}'))

    # Generate random invoke operation syntax.
    # 50% split between using $ExecutionContext invocation syntax versus IEX/Invoke-Expression/variable-obfuscated-'iex' syntax generated by Out-EncapsulatedInvokeExpression.
    $ExpressionToInvoke = $RandomInputVariable
    If(Get-Random -Input @(0..1))
    {
        # Randomly decide on invoke operation since we've applied an additional layer of string manipulation in above steps.
        $InvokeOption = Out-EncapsulatedInvokeExpression $ExpressionToInvoke
    }
    Else
    {
        $InvokeOption = (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ExpressionToInvoke + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
    }

    # Random case of $InvokeOption.
    $InvokeOption = ([Char[]]$InvokeOption.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

    # If $NoExit flag is defined in calling function then default to - stdin syntax. It will cause errors for other syntax options.
    If($NoExit)
    {
        $InvokeOption = '-'
    }

    # Set $PowerShellStdIn to value of $InvokeOption.
    $PowerShellStdIn = $InvokeOption

    # Random case of $PowerShellStdIn.
    $PowerShellStdIn = ([Char[]]$PowerShellStdIn.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

    # Run random PowerShell Stdin operation through the appropriate token obfuscators.
    If($PowerShellStdIn -ne '-')
    {
        # Run through all available token obfuscation functions in random order.
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption))
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption)) 'RandomWhitespace' 1
    }
    
    # For obfuscated commands generated for $PowerShellStdIn syntax, single-escape & < > and | characters for cmd.exe.
    ForEach($Char in @('<','>','|','&'))
    {
        # Remove single escaping and then escape all characters. This will handle single-escaped and not-escaped characters.
        If($PowerShellStdIn.Contains("$Char")) 
        {
            $PowerShellStdIn = $PowerShellStdIn.Replace("$Char","^$Char")
        }
    }
    
    # Escape double-quote with backslash for powershell.exe.
    If($PowerShellStdIn.Contains('"'))
    {
        $PowerShellStdIn = $PowerShellStdIn.Replace('"','\"')
    }

    Return $PowerShellStdIn
}


Function Out-RandomClipboardInvokeSyntax
{
<#
.SYNOPSIS

HELPER FUNCTION :: Generates randomized PowerShell syntax for invoking a command stored in the clipboard.

Invoke-Obfuscation Function: Out-RandomClipboardInvokeSyntax
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ObfuscatedTokenCommand, Out-EncapsulatedInvokeExpression (found in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomClipboardInvokeSyntax generates random PowerShell syntax for invoking a command stored in the clipboard. This technique is included to show the Blue Team that powershell.exe's command line arguments may not contain any contents of the command itself, but these could be stored in the parent/grandparent process if passed to powershell.exe via clipboard.

.EXAMPLE

C:\PS> Out-RandomClipboardInvokeSyntax

.  (  \"{0}{1}\" -f(  \"{1}{0}\"-f 'p','Add-Ty'  ),'e'  ) -AssemblyName (  \"{1}{0}{3}{2}\"-f ( \"{2}{0}{3}{1}\"-f'Wi','dows.Fo','em.','n'),(\"{1}{0}\"-f 'yst','S'),'s','rm'  )   ; (.( \"{0}\" -f'GV'  ) (\"{2}{3}{1}{0}{4}\" -f 'E','onCoNT','EXEC','UTi','XT')).\"Va`LuE\".\"inVOK`Ec`OMmANd\".\"inVOKe`SC`RIpT\"(( [sYsTEM.WInDOwS.foRMS.ClIPbOard]::( \"{1}{0}\"-f (\"{2}{1}{0}\" -f'XT','tTE','e'),'g').Invoke(  ) ) )   ;[System.Windows.Forms.Clipboard]::( \"{1}{0}\"-f'ar','Cle' ).Invoke(   )

.NOTES

This cmdlet is a helper function for Out-PowerShellLauncher's more sophisticated $LaunchType options where the PowerShell command is passed to powershell.exe via clipboard for command line obfuscation benefits.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Set variables necessary for loading appropriate class/type to be able to interact with the clipboard.
    $ReflectionAssembly    = Get-Random -Input @('System.Reflection.Assembly','Reflection.Assembly')
    $WindowsClipboard      = Get-Random -Input @('Windows.Clipboard','System.Windows.Clipboard')
    $WindowsFormsClipboard = Get-Random -Input @('System.Windows.Forms.Clipboard','Windows.Forms.Clipboard')
    
    # Randomly select flag argument substring for Add-Type -AssemblyCore.
    $FullArgument = "-AssemblyName"
    # Take into account the shorted flag of -AN as well.
    $AssemblyNameFlags = @()
    $AssemblyNameFlags += '-AN'
    For($Index=2; $Index -le $FullArgument.Length; $Index++)
    {
        $AssemblyNameFlags += $FullArgument.SubString(0,$Index)
    }
    $AssemblyNameFlag = Get-Random -Input $AssemblyNameFlags

    # Characters we will use to generate random variable name.
    # For simplicity do NOT include single- or double-quotes in this array.
    $CharsToRandomVarName  = @(0..9)
    $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')

    # Randomly choose variable name starting length.
    $RandomVarLength = (Get-Random -Input @(3..6))
   
    # Create random variable with characters from $CharsToRandomVarName.
    If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
    $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')

    # Generate random variable name.
    $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')

    # Generate paired random syntax options for: A) loading necessary class/assembly, B) retrieving contents from clipboard, and C) clearing/overwritting clipboard contents.
    $RandomClipSyntaxValue = Get-Random -Input @(1..3)
    Switch($RandomClipSyntaxValue)
    {
        1 {
            $LoadClipboardClassOption   = "Add-Type $AssemblyNameFlag PresentationCore"
            $GetClipboardContentsOption = "([$WindowsClipboard]::GetText())"
            $ClearClipboardOption       = "[$WindowsClipboard]::" + (Get-Random -Input @('Clear()',"SetText(' ')"))
        }
        2 {
            $LoadClipboardClassOption   = "Add-Type $AssemblyNameFlag System.Windows.Forms"
            $GetClipboardContentsOption = "([$WindowsFormsClipboard]::GetText())"
            $ClearClipboardOption       = "[$WindowsFormsClipboard]::" + (Get-Random -Input @('Clear()',"SetText(' ')"))
        }
        3 {
            $LoadClipboardClassOption   =  (Get-Random -Input @('[Void]','$NULL=',"`$$RandomVarName=")) + "[$ReflectionAssembly]::LoadWithPartialName('System.Windows.Forms')"
            $GetClipboardContentsOption = "([$WindowsFormsClipboard]::GetText())"
            $ClearClipboardOption       = "[$WindowsFormsClipboard]::" + (Get-Random -Input @('Clear()',"SetText(' ')"))
        }
        default {Write-Error "An invalid RandomClipSyntaxValue value ($RandomClipSyntaxValue) was passed to switch block for Out-RandomClipboardInvokeSyntax."; Exit;}
    }
    
    # Generate syntax options for invoking clipboard contents, including numerous ways to invoke with $ExecutionContext as a variable, including Get-Variable varname, Get-ChildItem Variable:varname, Get-Item Variable:varname, etc.
    $ExecContextVariables  = @()
    $ExecContextVariables += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + "'variable:" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "').Value"
    $ExecContextVariables += '(' + (Get-Random -Input @('Get-Variable','GV','Variable')) + ' ' + "'" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "'" + (Get-Random -Input (').Value',(' ' + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ')')))
    # Select random option from above.
    $ExecContextVariable = Get-Random -Input $ExecContextVariables

    # Generate random invoke operation syntax.
    # 50% split between using $ExecutionContext invocation syntax versus IEX/Invoke-Expression/variable-obfuscated-'iex' syntax generated by Out-EncapsulatedInvokeExpression.
    $ExpressionToInvoke = $GetClipboardContentsOption
    If(Get-Random -Input @(0..1))
    {
        # Randomly decide on invoke operation since we've applied an additional layer of string manipulation in above steps.
        $InvokeOption = Out-EncapsulatedInvokeExpression $ExpressionToInvoke
    }
    Else
    {
        $InvokeOption = (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ExpressionToInvoke + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
    }

    # Random case of $InvokeOption.
    $InvokeOption = ([Char[]]$InvokeOption.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''

    # Set final syntax for invoking clipboard contents.
    $PowerShellClip = $LoadClipboardClassOption + ' '*(Get-Random -Minimum 0 -Maximum 3) + ';' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $InvokeOption
    
    # Add syntax for clearing clipboard contents.
    $PowerShellClip = $PowerShellClip + ' '*(Get-Random -Minimum 0 -Maximum 3) + ';' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ClearClipboardOption

    # Run through all relevant token obfuscation functions except Type since it causes error for direct type casting relevant classes in a non-interactive PowerShell session.
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Member'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Member'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Command'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'CommandArgument'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Variable'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'String'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'RandomWhitespace'
    
    # For obfuscated commands generated for $PowerShellClip syntax, single-escape & < > and | characters for cmd.exe.
    ForEach($Char in @('<','>','|','&'))
    {
        # Remove single escaping and then escape all characters. This will handle single-escaped and not-escaped characters.
        If($PowerShellClip.Contains("$Char")) 
        {
            $PowerShellClip = $PowerShellClip.Replace("$Char","^$Char")
        }
    }
    
    # Escape double-quote with backslash for powershell.exe.
    If($PowerShellClip.Contains('"'))
    {
        $PowerShellClip = $PowerShellClip.Replace('"','\"')
    }

    Return $PowerShellClip
}