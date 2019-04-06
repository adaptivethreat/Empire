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



Function Out-ObfuscatedStringCommand
{
<#
.SYNOPSIS

Master function that orchestrates the application of all string-based obfuscation functions to provided PowerShell script.

Invoke-Obfuscation Function: Out-ObfuscatedStringCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-EncapsulatedInvokeExpression (located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedStringCommand orchestrates the application of all string-based obfuscation functions (casting ENTIRE command to a string a performing string obfuscation functions) to provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $ObfuscationLevel is defined then Out-ObfuscatedStringCommand will automatically choose a random obfuscation level.
The available ObfuscationLevel/function mappings are:
1 --> Out-StringDelimitedAndConcatenated
2 --> Out-StringDelimitedConcatenatedAndReordered
3 --> Out-StringReversed

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER ObfuscationLevel

(Optional) Specifies the obfuscation level for the given input PowerShell payload. If not defined then Out-ObfuscatedStringCommand will automatically choose a random obfuscation level. 
The available ObfuscationLevel/function mappings are:
1 --> Out-StringDelimitedAndConcatenated
2 --> Out-StringDelimitedConcatenatedAndReordered
3 --> Out-StringReversed

.EXAMPLE

C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 1

IEX ((('Write-H'+'ost x'+'lcHello'+' Wor'+'ld!xlc -F'+'oregroundC'+'o'+'lor Gre'+'en'+'; Write-Host '+'xlcObf'+'u'+'sc'+'ation '+'Rocks!xl'+'c'+' '+'-'+'Foregrou'+'nd'+'C'+'olor Green')  -Replace 'xlc',[Char]39) )

C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 2

IEX( (("{17}{1}{6}{19}{14}{3}{5}{13}{16}{11}{20}{15}{10}{12}{2}{4}{8}{18}{7}{9}{0}" -f ' Green','-H',' ',' ','R','-Foregr','ost qR9He','!qR9 -Foregr','o','oundColor','catio',' ','n','oundColor','qR9','bfus',' Green; Write-Host','Write','cks','llo World!','qR9O')).Replace('qR9',[String][Char]39))

C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 3

$I4 ="noisserpxE-ekovnI|)93]rahC[]gnirtS[,'1Yp'(ecalpeR.)'ne'+'erG roloCd'+'nuo'+'rgero'+'F- 1'+'Y'+'p!s'+'kcoR'+' noit'+'a'+'cs'+'ufbO'+'1'+'Yp '+'tsoH'+'-etirW'+' ;'+'neer'+'G '+'rol'+'oCdnu'+'orger'+'o'+'F'+'-'+' 1'+'Yp'+'!dlroW '+'olleH1Yp '+'t'+'s'+'oH-et'+'irW'( " ;$I4[ -1 ..- ($I4.Length ) ] -Join '' | Invoke-Expression

.NOTES

Out-ObfuscatedStringCommand orchestrates the application of all string-based obfuscation functions (casting ENTIRE command to a string a performing string obfuscation functions) to provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $ObfuscationLevel is defined then Out-ObfuscatedStringCommand will automatically choose a random obfuscation level.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('1', '2', '3')]
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $ObfuscationLevel = (Get-Random -Input @(1..3)) # Default to random obfuscation level if $ObfuscationLevel isn't defined
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

    # Set valid obfuscation levels for current token type.
    $ValidObfuscationLevels = @(0,1,2,3)
    
    # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
    If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}  
    
    Switch($ObfuscationLevel)
    {
        0 {Continue}
        1 {$ScriptString = Out-StringDelimitedAndConcatenated $ScriptString}
        2 {$ScriptString = Out-StringDelimitedConcatenatedAndReordered $ScriptString}
        3 {$ScriptString = Out-StringReversed $ScriptString}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for String Obfuscation."; Exit}
    }

    Return $ScriptString
}


Function Out-StringDelimitedAndConcatenated
{
<#
.SYNOPSIS

Generates delimited and concatenated version of input PowerShell command.

Invoke-Obfuscation Function: Out-StringDelimitedAndConcatenated
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ConcatenatedString (located in Out-ObfuscatedTokenCommand.ps1), Out-EncapsulatedInvokeExpression (located in Out-ObfuscatedStringCommand.ps1), Out-RandomCase (located in Out-ObfuscatedToken.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-StringDelimitedAndConcatenated delimits and concatenates an input PowerShell command. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER PassThru

(Optional) Outputs the option to not encapsulate the result in an invocation command.

.EXAMPLE

C:\PS> Out-StringDelimitedAndConcatenated "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"

(('Write-Ho'+'s'+'t'+' {'+'0'+'}'+'Hell'+'o Wor'+'l'+'d!'+'{'+'0'+'} -Foreground'+'Color G'+'ree'+'n; Writ'+'e-'+'H'+'ost {0}Obf'+'usc'+'a'+'tion R'+'o'+'ck'+'s!{'+'0} -Fo'+'reg'+'ro'+'undColor'+' '+'Gree'+'n')-F[Char]39) | Invoke-Expression

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Switch]
        $PassThru
    )

    # Characters we will substitute (in random order) with randomly generated delimiters.
    $CharsToReplace = @('$','|','`','\','"',"'")
    $CharsToReplace = (Get-Random -Input $CharsToReplace -Count $CharsToReplace.Count)

    # If $ScriptString does not contain any characters in $CharsToReplace then simply return as is.
    $ContainsCharsToReplace = $FALSE
    ForEach($CharToReplace in $CharsToReplace)
    {
        If($ScriptString.Contains($CharToReplace))
        {
            $ContainsCharsToReplace = $TRUE
            Break
        }
    }
    If(!$ContainsCharsToReplace)
    {
        # Concatenate $ScriptString as a string and then encapsulate with parentheses.
        $ScriptString = Out-ConcatenatedString $ScriptString "'"
        $ScriptString = '(' + $ScriptString + ')'

        If(!$PSBoundParameters['PassThru'])
        {
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
        }

        Return $ScriptString
    }
    
    # Characters we will use to generate random delimiters to replace the above characters.
    # For simplicity do NOT include single- or double-quotes in this array.
    $CharsToReplaceWith  = @(0..9)
    $CharsToReplaceWith += @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
    $CharsToReplaceWith += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
    $DelimiterLength = 3
    
    # Multi-dimensional table containing delimiter/replacement key pairs for building final command to reverse substitutions.
    $DelimiterTable = @()
    
    # Iterate through and replace each character in $CharsToReplace in $ScriptString with randomly generated delimiters.
    ForEach($CharToReplace in $CharsToReplace)
    {
        If($ScriptString.Contains($CharToReplace))
        {
            # Create random delimiter of length $DelimiterLength with characters from $CharsToReplaceWith.
            If($CharsToReplaceWith.Count -lt $DelimiterLength) {$DelimiterLength = $CharsToReplaceWith.Count}
            $Delim = (Get-Random -Input $CharsToReplaceWith -Count $DelimiterLength) -Join ''
            
            # Keep generating random delimiters until we find one that is not a substring of $ScriptString.
            While($ScriptString.ToLower().Contains($Delim.ToLower()))
            {
                $Delim = (Get-Random -Input $CharsToReplaceWith -Count $DelimiterLength) -Join ''
                If($DelimiterLength -lt $CharsToReplaceWith.Count)
                {
                    $DelimiterLength++
                }
            }
            
            # Add current delimiter/replacement key pair for building final command to reverse substitutions.
            $DelimiterTable += , @($Delim,$CharToReplace)

            # Replace current character to replace with the generated delimiter
            $ScriptString = $ScriptString.Replace($CharToReplace,$Delim)
        }
    }

    # Add random quotes to delimiters in $DelimiterTable.
    $DelimiterTableWithQuotes = @()
    ForEach($DelimiterArray in $DelimiterTable)
    {
        $Delimiter    = $DelimiterArray[0]
        $OriginalChar = $DelimiterArray[1]
        
        # Randomly choose between a single quote and double quote.
        $RandomQuote = Get-Random -InputObject @("'","`"")
        
        # Make sure $RandomQuote is opposite of $OriginalChar contents if it is a single- or double-quote.
        If($OriginalChar -eq "'") {$RandomQuote = '"'}
        Else {$RandomQuote = "'"}

        # Add quotes.
        $Delimiter = $RandomQuote + $Delimiter + $RandomQuote
        $OriginalChar = $RandomQuote + $OriginalChar + $RandomQuote
        
        # Add random quotes to delimiters in $DelimiterTable.
        $DelimiterTableWithQuotes += , @($Delimiter,$OriginalChar)
    }

    # Reverse the delimiters when building back out the reversing command.
    [Array]::Reverse($DelimiterTable)
    
    # Select random method for building command to reverse the above substitutions to execute the original command.
    # Avoid using the -f format operator (switch option 3) if curly braces are found in $ScriptString.
    If(($ScriptString.Contains('{')) -AND ($ScriptString.Contains('}')))
    {
        $RandomInput = Get-Random -Input (1..2)
    }
    Else
    {
        $RandomInput = Get-Random -Input (1..3)
    }

    # Randomize the case of selected variable syntaxes.
    $StringStr   = Out-RandomCase 'string'
    $CharStr     = Out-RandomCase 'char'
    $ReplaceStr  = Out-RandomCase 'replace'
    $CReplaceStr = Out-RandomCase 'creplace'

    Switch($RandomInput) {
        1 {
            # 1) .Replace

            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""

            ForEach($DelimiterArray in $DelimiterTableWithQuotes)
            {
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                
                # Randomly decide if $OriginalChar will be displayed in ASCII representation or plaintext in $ReversingCommand.
                # This is to allow for simpler string manipulation on the command line.
                # Place priority on handling if $OriginalChar is a single- and double-quote.
                If($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$StringStr][$CharStr]39"
                    $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                ElseIf($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$StringStr][$CharStr]34"
                }
                Else
                {
                    If(Get-Random -Input (0..1))
                    {
                        $OriginalChar = "[$StringStr][$CharStr]" + [Int][Char]$OriginalChar[1]
                    }
                }
                
                # Randomly select if $Delimiter will be displayed in ASCII representation instead of plaintext in $ReversingCommand. 
                If(Get-Random -Input (0..1))
                {
                    # Convert $Delimiter string into a concatenation of [Char] representations of each characters.
                    # This is to avoid redundant replacement of single quotes if this function is run numerous times back-to-back.
                    $DelimiterCharSyntax = ""
                    For($i=1; $i -lt $Delimiter.Length-1; $i++)
                    {
                        $DelimiterCharSyntax += "[$CharStr]" + [Int][Char]$Delimiter[$i] + '+'
                    }
                    $Delimiter = '(' + $DelimiterCharSyntax.Trim('+') + ')'
                }
                
                # Add reversing commands to $ReversingCommand.
                $ReversingCommand = ".$ReplaceStr($Delimiter,$OriginalChar)" + $ReversingCommand
            }

            # Concatenate $ScriptString as a string and then encapsulate with parentheses.
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'

            # Add reversing commands to $ScriptString.
            $ScriptString = $ScriptString + $ReversingCommand
        }
        2 {
            # 2) -Replace/-CReplace

            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""

            ForEach($DelimiterArray in $DelimiterTableWithQuotes)
            {
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                
                # Randomly decide if $OriginalChar will be displayed in ASCII representation or plaintext in $ReversingCommand.
                # This is to allow for simpler string manipulation on the command line.
                # Place priority on handling if $OriginalChar is a single- or double-quote.
                If($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$CharStr]34"
                }
                ElseIf($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$CharStr]39"; $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                Else
                {
                    $OriginalChar = "[$CharStr]" + [Int][Char]$OriginalChar[1]
                }
                
                # Randomly select if $Delimiter will be displayed in ASCII representation instead of plaintext in $ReversingCommand. 
                If(Get-Random -Input (0..1))
                {
                    # Convert $Delimiter string into a concatenation of [Char] representations of each characters.
                    # This is to avoid redundant replacement of single quotes if this function is run numerous times back-to-back.
                    $DelimiterCharSyntax = ""
                    For($i=1; $i -lt $Delimiter.Length-1; $i++)
                    {
                        $DelimiterCharSyntax += "[$CharStr]" + [Int][Char]$Delimiter[$i] + '+'
                    }
                    $Delimiter = '(' + $DelimiterCharSyntax.Trim('+') + ')'
                }
                
                # Randomly choose between -Replace and the lesser-known case-sensitive -CReplace.
                $Replace = (Get-Random -Input @("-$ReplaceStr","-$CReplaceStr"))

                # Add reversing commands to $ReversingCommand. Whitespace before and after $Replace is optional.
                $ReversingCommand = ' '*(Get-Random -Minimum 0 -Maximum 3) + $Replace + ' '*(Get-Random -Minimum 0 -Maximum 3) + "$Delimiter,$OriginalChar" + $ReversingCommand                
            }

            # Concatenate $ScriptString as a string and then encapsulate with parentheses.
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'

            # Add reversing commands to $ScriptString.
            $ScriptString = '(' + $ScriptString + $ReversingCommand + ')'
        }
        3 {
            # 3) -f format operator

            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""
            $Counter = 0

            # Iterate delimiters in reverse for simpler creation of the proper order for $ReversingCommand.
            For($i=$DelimiterTableWithQuotes.Count-1; $i -ge 0; $i--)
            {
                $DelimiterArray = $DelimiterTableWithQuotes[$i]
                
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                
                $DelimiterNoQuotes = $Delimiter.SubString(1,$Delimiter.Length-2)
                
                # Randomly decide if $OriginalChar will be displayed in ASCII representation or plaintext in $ReversingCommand.
                # This is to allow for simpler string manipulation on the command line.
                # Place priority on handling if $OriginalChar is a single- or double-quote.
                If($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$CharStr]34"
                }
                ElseIf($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$CharStr]39"; $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                Else
                {
                    $OriginalChar = "[$CharStr]" + [Int][Char]$OriginalChar[1]
                }
                
                # Build out delimiter order to add as arguments to the final -f format operator.
                $ReversingCommand = $ReversingCommand + ",$OriginalChar"

                # Substitute each delimited character with placeholder for -f format operator.
                $ScriptString = $ScriptString.Replace($DelimiterNoQuotes,"{$Counter}")

                $Counter++
            }
            
            # Trim leading comma from $ReversingCommand.
            $ReversingCommand = $ReversingCommand.Trim(',')

            # Concatenate $ScriptString as a string and then encapsulate with parentheses.
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'
            
            # Add reversing commands to $ScriptString. Whitespace before and after -f format operator is optional.
            $FormatOperator = (Get-Random -Input @('-f','-F'))

            $ScriptString = '(' + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 3) + $FormatOperator + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ReversingCommand + ')'
        }
        default {Write-Error "An invalid `$RandomInput value ($RandomInput) was passed to switch block."; Exit;}
    }
    
    # Encapsulate $ScriptString in necessary IEX/Invoke-Expression(s) if -PassThru switch was not specified.
    If(!$PSBoundParameters['PassThru'])
    {
        $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
    }

    Return $ScriptString
}


Function Out-StringDelimitedConcatenatedAndReordered
{
<#
.SYNOPSIS

Generates delimited, concatenated and reordered version of input PowerShell command.

Invoke-Obfuscation Function: Out-StringDelimitedConcatenatedAndReordered
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated (located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-StringDelimitedConcatenatedAndReordered delimits, concatenates and reorders the concatenated substrings of an input PowerShell command. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER PassThru

(Optional) Outputs the option to not encapsulate the result in an invocation command.

.EXAMPLE

C:\PS> Out-StringDelimitedConcatenatedAndReordered "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"

(("{16}{5}{6}{14}{3}{19}{15}{10}{18}{17}{0}{2}{7}{8}{12}{9}{11}{4}{13}{1}"-f't','en','ion R','9 -Fore','Gr','e-Host 0i9Hello W','or','ocks!0i9 -Fo','regroun','olo','ite-Hos','r ','dC','e','ld!0i','; Wr','Writ','sca','t 0i9Obfu','groundColor Green')).Replace('0i9',[String][Char]39) |IEX

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 2
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Switch]
        $PassThru
    )

    If(!$PSBoundParameters['PassThru'])
    {
        # Convert $ScriptString to delimited and concatenated string and encapsulate with invocation.
        $ScriptString = Out-StringDelimitedAndConcatenated $ScriptString
    }
    Else
    {
        # Convert $ScriptString to delimited and concatenated string and do no encapsulate with invocation.
        $ScriptString = Out-StringDelimitedAndConcatenated $ScriptString -PassThru
    }

    # Parse out concatenated strings to re-order them.
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    $GroupStartCount = 0
    $ConcatenatedStringsIndexStart = $NULL
    $ConcatenatedStringsIndexEnd   = $NULL
    $ConcatenatedStringsArray = @()
    For($i=0; $i -le $Tokens.Count-1; $i++) {
        $Token = $Tokens[$i]

        If(($Token.Type -eq 'GroupStart') -AND ($Token.Content -eq '('))
        {
            $GroupStartCount = 1
            $ConcatenatedStringsIndexStart = $Token.Start+1
        }
        ElseIf(($Token.Type -eq 'GroupEnd') -AND ($Token.Content -eq ')') -OR ($Token.Type -eq 'Operator') -AND ($Token.Content -ne '+'))
        {
            $GroupStartCount--
            $ConcatenatedStringsIndexEnd = $Token.Start
            # Stop parsing concatenated string.
            If(($GroupStartCount -eq 0) -AND ($ConcatenatedStringsArray.Count -gt 0))
            {
                Break
            }
        }
        ElseIf(($GroupStartCount -gt 0) -AND ($Token.Type -eq 'String'))
        {
            $ConcatenatedStringsArray += $Token.Content
        }
        ElseIf($Token.Type -ne 'Operator')
        {
            # If something other than a string or operator appears then we're not dealing with a pure string concatenation. Thus we reset the group start and the concatenated strings array.
            # This only became an issue once the invocation syntax went from IEX/Invoke-Expression to concatenations like .($ShellId[1]+$ShellId[13]+'x')
            $GroupStartCount = 0
            $ConcatenatedStringsArray = @()
        }
    }

    $ConcatenatedStrings = $ScriptString.SubString($ConcatenatedStringsIndexStart,$ConcatenatedStringsIndexEnd-$ConcatenatedStringsIndexStart)

    # Return $ScriptString as-is if there is only one substring as it would gain nothing to "reorder" a single substring.
    If($ConcatenatedStringsArray.Count -le 1)
    {
        Return $ScriptString
    }

    # Randomize the order of the concatenated strings.
    $RandomIndexes = (Get-Random -Input (0..$($ConcatenatedStringsArray.Count-1)) -Count $ConcatenatedStringsArray.Count)
    
    $Arguments1 = ''
    $Arguments2 = @('')*$ConcatenatedStringsArray.Count
    For($i=0; $i -lt $ConcatenatedStringsArray.Count; $i++)
    {
        $RandomIndex = $RandomIndexes[$i]
        $Arguments1 += '{' + $RandomIndex + '}'
        $Arguments2[$RandomIndex] = "'" + $ConcatenatedStringsArray[$i] + "'"
    }
    
    # Whitespace is not required before or after the -f operator.
    $ScriptStringReordered = '(' + '"' + $Arguments1 + '"' + ' '*(Get-Random @(0..1)) + '-f' + ' '*(Get-Random @(0..1)) + ($Arguments2 -Join ',') + ')'

    # Add re-ordered $ScriptString back into the original $ScriptString context.
    $ScriptString = $ScriptString.SubString(0,$ConcatenatedStringsIndexStart) + $ScriptStringReordered + $ScriptString.SubString($ConcatenatedStringsIndexEnd)

    Return $ScriptString
}


Function Out-StringReversed
{
<#
.SYNOPSIS

Generates concatenated and reversed version of input PowerShell command.

Invoke-Obfuscation Function: Out-StringReversed
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ConcatenatedString, Out-RandomCase (both are located in Out-ObfuscatedToken.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-StringReversed concatenates and reverses an input PowerShell command. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptString

Specifies the string containing your payload.

.EXAMPLE

C:\PS> Out-StringReversed "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"

sv 6nY  ("XEI | )93]rahC[ f-)'n'+'eer'+'G'+' roloC'+'dnuo'+'rgeroF-'+' '+'}0{!sk'+'co'+'R '+'noitacsufb'+'O'+'}0'+'{ ts'+'oH-'+'etirW ;neer'+'G'+' rolo'+'C'+'dnu'+'orgeroF- }0{!d'+'l'+'roW'+' olleH}0{ tsoH-et'+'ir'+'W'(( ");IEX ( (  gcI  vARiaBlE:6ny  ).valUE[ -1..-( (  gcI  vARiaBlE:6ny  ).valUE.Length ) ]-Join '' )

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    # Remove any special characters to simplify dealing with the reversed $ScriptString on the command line.
    $ScriptString = Out-ObfuscatedStringCommand ([ScriptBlock]::Create($ScriptString)) 1

    # Reverse $ScriptString.
    $ScriptStringReversed = $ScriptString[-1..-($ScriptString.Length)] -Join ''
    
    # Characters we will use to generate random variable names.
    # For simplicity do NOT include single- or double-quotes in this array.
    $CharsToRandomVarName  = @(0..9)
    $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')

    # Randomly choose variable name starting length.
    $RandomVarLength = (Get-Random -Input @(3..6))
   
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
    # Handle both <varname> and <variable:varname> syntaxes depending on which option is chosen concerning GET variable syntax.
    $RandomVarNameMaybeConcatenated = $RandomVarName
    $RandomVarNameMaybeConcatenatedWithVariablePrepended = 'variable:' + $RandomVarName
    If((Get-Random -Input @(0..1)) -eq 0)
    {
        $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName (Get-Random -Input @('"',"'"))) + ')'
        $RandomVarNameMaybeConcatenatedWithVariablePrepended = '(' + (Out-ConcatenatedString "variable:$RandomVarName" (Get-Random -Input @('"',"'"))) + ')'
    }

    # Placeholder for values to be SET in variable differently in each Switch statement below.
    $RandomVarValPlaceholder = '<[)(]>'

    # Generate random variable SET syntax.
    $RandomVarSetSyntax  = @()
    $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $RandomVarValPlaceholder
    $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $RandomVarValPlaceholder + ' '*(Get-Random @(0..2)) + ')'
    
    # Randomly choose from above variable syntaxes.
    $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)

    # Randomize the case of selected variable syntaxes.
    $RandomVarSet = Out-RandomCase $RandomVarSet
    
    # Generate random variable GET syntax.
    $RandomVarGetSyntax  = @()
    $RandomVarGetSyntax += '$' + $RandomVarName
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('Get-Variable','Variable')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + (Get-Random -Input ((' '*(Get-Random @(0..2)) + ').Value'),(' '*(Get-Random @(1..2)) + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ' '*(Get-Random @(0..2)) + ')')))
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(0..2)) + ').Value'
    
    # Randomly choose from above variable syntaxes.
    $RandomVarGet = (Get-Random -Input $RandomVarGetSyntax)

    # Randomize the case of selected variable syntaxes.
    $RandomVarGet = Out-RandomCase $RandomVarGet

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exists then we could use even more syntax: $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info: https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += '$OFS' + ' '*(Get-Random -Input @(0,1)) + '=' + ' '*(Get-Random -Input @(0,1))  + "''"
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)

    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)

    # Randomize the case of selected variable syntaxes.
    $SetOfsVar            = Out-RandomCase $SetOfsVar
    $SetOfsVarBack        = Out-RandomCase $SetOfsVarBack
    $StringStr            = Out-RandomCase 'string'
    $JoinStr              = Out-RandomCase 'join'
    $LengthStr            = Out-RandomCase 'length'
    $ArrayStr             = Out-RandomCase 'array'
    $ReverseStr           = Out-RandomCase 'reverse'
    $CharStr              = Out-RandomCase 'char'
    $RightToLeftStr       = Out-RandomCase 'righttoleft'
    $RegexStr             = Out-RandomCase 'regex'
    $MatchesStr           = Out-RandomCase 'matches'
    $ValueStr             = Out-RandomCase 'value'
    $ForEachObject        = Out-RandomCase (Get-Random -Input @('ForEach-Object','ForEach','%'))

    # Select random method for building command to reverse the now-reversed $ScriptString to execute the original command.
    Switch(Get-Random -Input (1..3)) {
        1 {
            # 1) $StringVar = $String; $StringVar[-1..-($StringVar.Length)] -Join ''
            
            # Replace placeholder with appropriate value for this Switch statement.
            $RandomVarSet = $RandomVarSet.Replace($RandomVarValPlaceholder,('"' + ' '*(Get-Random -Input @(0,1)) + $ScriptStringReversed + ' '*(Get-Random -Input @(0,1)) + '"'))

            # Set $ScriptStringReversed as environment variable $Random.
            $ScriptString = $RandomVarSet + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1))
            
            $RandomVarGet = $RandomVarGet + '[' + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '1' + ' '*(Get-Random -Input @(0,1)) + '..' + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ".$LengthStr" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ']'

            # Build out random syntax depending on whether -Join is prepended or -Join '' is appended.
            # Now also includes [String]::Join .Net syntax and [String] syntax after modifying $OFS variable to ''.
            $JoinOptions  = @()
            $JoinOptions += "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet
            $JoinOptions += $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''"
            $JoinOptions += "[$StringStr]::$JoinStr" + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $RandomVarGet) + ' '*(Get-Random -Input @(0,1)) + ')'
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $JoinOption = (Get-Random -Input $JoinOptions)
            
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $JoinOption = Out-EncapsulatedInvokeExpression $JoinOption
            
            $ScriptString = $ScriptString + $JoinOption
        }
        2 {
            # 2) $StringVar = [Char[]]$String; [Array]::Reverse($StringVar); $StringVar -Join ''
            
            # Replace placeholder with appropriate value for this Switch statement.
            $RandomVarSet = $RandomVarSet.Replace($RandomVarValPlaceholder,("[$CharStr[" + ' '*(Get-Random -Input @(0,1)) + ']' + ' '*(Get-Random -Input @(0,1)) + ']' + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"'))

            # Set $ScriptStringReversed as environment variable $Random.
            $ScriptString = $RandomVarSet + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1))
            $ScriptString = $ScriptString + ' '*(Get-Random -Input @(0,1)) + "[$ArrayStr]::$ReverseStr(" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ';'

            # Build out random syntax depending on whether -Join is prepended or -Join '' is appended.
            # Now also includes [String]::Join .Net syntax and [String] syntax after modifying $OFS variable to ''.
            $JoinOptions  = @()
            $JoinOptions += "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet
            $JoinOptions += $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''"
            $JoinOptions += "[$StringStr]::$JoinStr" + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')'
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $JoinOption = (Get-Random -Input $JoinOptions)
            
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $JoinOption = Out-EncapsulatedInvokeExpression $JoinOption
            
            $ScriptString = $ScriptString + $JoinOption
        }
        3 {
            # 3) -Join[Regex]::Matches($String,'.','RightToLeft')

            # Randomly choose to use 'RightToLeft' or concatenated version of this string in $JoinOptions below.
            If(Get-Random -Input (0..1))
            {
                $RightToLeft = Out-ConcatenatedString $RightToLeftStr "'"
            }
            Else
            {
                $RightToLeft = "'$RightToLeftStr'"
            }
            
            # Build out random syntax depending on whether -Join is prepended or -Join '' is appended.
            # Now also includes [String]::Join .Net syntax and [String] syntax after modifying $OFS variable to ''.
            $JoinOptions  = @()
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' +  ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + "[$StringStr]::$JoinStr(" + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '$_' + ".$ValueStr" + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' +          ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '$_' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'             + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $ScriptString = (Get-Random -Input $JoinOptions)
            
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
        }
        default {Write-Error "An invalid value was passed to switch block."; Exit;}
    }
    
    # Perform final check to remove ticks if they now precede lowercase special characters after the string is reversed.
    # E.g. "testin`G" in reverse would be "G`nitset" where `n would be interpreted as a newline character.
    $SpecialCharacters = @('a','b','f','n','r','u','t','v','0')
    ForEach($SpecialChar in $SpecialCharacters)
    {
        If($ScriptString.Contains("``"+$SpecialChar))
        {
            $ScriptString = $ScriptString.Replace("``"+$SpecialChar,$SpecialChar)
        }
    }
    
    Return $ScriptString
}


Function Out-EncapsulatedInvokeExpression
{
<#
.SYNOPSIS

HELPER FUNCTION :: Generates random syntax for invoking input PowerShell command.

Invoke-Obfuscation Function: Out-EncapsulatedInvokeExpression
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncapsulatedInvokeExpression generates random syntax for invoking input PowerShell command. It uses a combination of IEX and Invoke-Expression as well as ordering (IEX $Command , $Command | IEX).

.PARAMETER ScriptString

Specifies the string containing your payload.

.EXAMPLE

C:\PS> Out-EncapsulatedInvokeExpression {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green}

Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green|Invoke-Expression

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 1
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 2
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    # The below code block is copy/pasted into almost every encoding function so they can maintain zero dependencies and work on their own (I admit using this bad coding practice).
    # Changes to below InvokeExpressionSyntax block should also be copied to those functions.
    # Generate random invoke operation syntax.
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
    $InvokeExpression = Out-RandomCase $InvokeExpression
    
    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ScriptString + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $ScriptString + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression

    $ScriptString = (Get-Random -Input $InvokeOptions)

    Return $ScriptString
}