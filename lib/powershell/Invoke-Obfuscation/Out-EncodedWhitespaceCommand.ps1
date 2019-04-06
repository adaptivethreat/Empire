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



Function Out-EncodedWhitespaceCommand
{
<#
.SYNOPSIS

Generates Whitespace encoded payload for a PowerShell command or script. Optionally it adds command line output to final command.

Invoke-Obfuscation Function: Out-EncodedWhitespaceCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncodedWhitespaceCommand encodes an input PowerShell scriptblock or path as a Whitespace-and-Tab encoded payload. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

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

C:\PS> Out-EncodedWhitespaceCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive

powershell  -NoP  -NonInterac     "'         	        		  	  	     		  	 	      		  	  	       		  	 	  		     	      		        	   		  	  	  		  	  	      		  	  	       		    	   		    	          		        	   		  	 	  		  	 	         		  	 	         		  	  	  		    	   		         	        		  	  	  		  	  	     		  	 	         		  	 	 		    	    		    	          		    	   		     	      		        	 		  	  	  		  	  	     		  	 	  		  	 	    		  	  	     		  	  	  		  	  	        		  	  	 		  	 	 		       	        		  	  	  		  	 	         		  	  	  		  	  	     		    	   		        	  		  	  	     		  	 	  		  	 	  		  	  	 		      	          		    	   		         	        		  	  	     		  	 	      		  	  	       		  	 	  		     	      		        	   		  	  	  		  	  	      		  	  	       		    	   		    	          		        	          		          	         		  	 	   		  	  	        		  	  	      		          	          		          	        		  	  	       		  	 	      		  	  	  		  	  	 		    	   		         	   		  	  	  		          	          		  	 	        		  	  	      		    	    		    	          		    	   		     	      		        	 		  	  	  		  	  	     		  	 	  		  	 	    		  	  	     		  	  	  		  	  	        		  	  	 		  	 	 		       	        		  	  	  		  	 	         		  	  	  		  	  	     		    	   		        	  		  	  	     		  	 	  		  	 	  		  	  	 '|%{$uXOrcSp= $_ -CSplIt '		' | %{'	' ; $_ -CSplIt '	' |% { $_.lEngth- 1}} ; .( ([string]''.LAstINDEXOFANy)[92,95,96]-join'')( (($uXOrcSp[0..($uXOrcSp.lEngth-1)] -join'' ).TrIm( '	 ').SPLIT('	' ) |% {([chAr][iNt]$_) })-join '' ) }"

C:\PS> Out-EncodedWhitespaceCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive -PassThru

'									 								  		 		 					  		 	 						  		 		 							  		 	 		  					 						  								 			  		 		 		  		 		 						  		 		 							  				 			  				 										  								 			  		 	 		  		 	 									  		 	 									  		 		 		  				 			  									 								  		 		 		  		 		 					  		 	 									  		 	 	  				 				  				 										  				 			  					 						  								 	  		 		 		  		 		 					  		 	 		  		 	 				  		 		 					  		 		 		  		 		 								  		 		 	  		 	 	  							 								  		 		 		  		 	 									  		 		 		  		 		 					  				 			  								 		  		 		 					  		 	 		  		 	 		  		 		 	  						 										  				 			  									 								  		 		 					  		 	 						  		 		 							  		 	 		  					 						  								 			  		 		 		  		 		 						  		 		 							  				 			  				 										  								 										  										 									  		 	 			  		 		 								  		 		 						  										 										  										 								  		 		 							  		 	 						  		 		 		  		 		 	  				 			  									 			  		 		 		  										 										  		 	 								  		 		 						  				 				  				 										  				 			  					 						  								 	  		 		 		  		 		 					  		 	 		  		 	 				  		 		 					  		 		 		  		 		 								  		 		 	  		 	 	  							 								  		 		 		  		 	 									  		 		 		  		 		 					  				 			  								 		  		 		 					  		 	 		  		 	 		  		 		 	'| % {$gyPrfqv= $_ -csPLiT '  '|% { ' ';$_.SPlIT(' ') | %{$_.LEngth - 1 }}; [StRINg]::joIn( '',((-jOin ($gyPrfqv[0..($gyPrfqv.LEngth-1)])).triM( '  ' ).SPlIT(' ' )|% { ( [CHAr][iNt]$_)}))|&( $eNv:CoMSPEC[4,26,25]-jOiN'')}

.NOTES

Inspiration for this encoding technique came from Casey Smith (@subTee) while at the 2017 BlueHat IL conference.
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
    
    # Convert $ScriptString to an ASCII-encoded array.
    $AsciiArray = [Int[]][Char[]]$ScriptString
    
    # Encode ASCII array with defined EncodingChar and DelimiterChar (randomly-selected as whitespace and tab, [Char]9).
    $RandomIndex  = Get-Random -Input @(0,1)
    $EncodedArray = @()
    $EncodingChar       = @(' ',[Char]9)[$RandomIndex]
    $DigitDelimiterChar = @([Char]9,' ')[$RandomIndex]
   
    # Enumerate each ASCII value and (ultimately) store decoded ASCII values in $EncodedArray array.
    ForEach($AsciiValue in $AsciiArray)
    {
        $EncodedAsciiValueArray = @()
        # Enumerate each digit in current ASCII value and convert it to DelimiterChar*Digit.
        ForEach($Digit in [Char[]][String]$AsciiValue)
        {
            $EncodedAsciiValueArray += [String]$EncodingChar*([Int][String]$Digit + 1)
        }
        $EncodedArray += ($EncodedAsciiValueArray -Join $DigitDelimiterChar)
    }

    # Set $IntDelimiterChar to be two instances of $DigitDelimiterChar.
    # $IntDelimiterChar will essentially be like the comma in the original ASCII array.
    $IntDelimiterChar = $DigitDelimiterChar + $DigitDelimiterChar

    # Join together final $EncodedString with delimiter selected above.
    $EncodedString = ($EncodedArray -Join $IntDelimiterChar)
    
    # Generate random case versions for necessary operations.
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $SplitMethod   = Get-Random -Input @('-Split','-CSplit','-ISplit')
    $Trim          = Get-Random -Input @('Trim','TrimStart')
    $StrJoin       = ([Char[]]'[String]::Join'      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'                | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Length        = ([Char[]]'Length'              | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SplitMethod   = ([Char[]]$SplitMethod          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SplitMethod2  = ([Char[]]'Split'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Trim          = ([Char[]]$Trim                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SplitOnDelim  = Get-Random -Input @(" $SplitMethod '$DigitDelimiterChar'",".$SplitMethod2('$DigitDelimiterChar')")

    # Generate random variable name to store the script's intermediate state while being reassembled.
    $RandomScriptVar = (Get-Random -Input @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') -Count (Get-Random -Input @(5..8)) | ForEach-Object {$UpperLowerChar = $_; If(Get-Random -Input @(0..1)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $UpperLowerChar}) -Join ''
    
    # Build the first part of the decoding routine.
    $ScriptStringPart1 = "'$EncodedString'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + "`$$RandomScriptVar" + ' '*(Get-Random -Input @(0,1)) + '=' + ' '*(Get-Random -Input @(0,1)) + "`$_ $SplitMethod '$IntDelimiterChar'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar'" + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1)) + "`$_$SplitOnDelim" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + "`$_.$Length" + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '1' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ';'
    
    # Randomly select between various conversion syntax options.
    $RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + "[$Int]" + ' '*(Get-Random -Input @(0,1)) + "`$_"
    $RandomConversionSyntax += "[$Int]" + ' '*(Get-Random -Input @(0,1)) + "`$_" + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]"
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)
    
    # Create array syntax for encoded $ScriptString as alternative to .Split/-Split syntax.
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$EncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))}

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
    
    # Generate the code that will iterate through each element of the array.
    $BaseScriptArray1  = "`$$RandomScriptVar[0..(`$$RandomScriptVar.$Length-1)]"
    
    # Generate random JOIN syntax for all above options.
    $NewScriptArray1   = @()
    $NewScriptArray1  += $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray1  += $Join + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray1  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray1  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    
    # Randomly select one of the above commands.
    $NewScript1 = (Get-Random -Input $NewScriptArray1)
    
    # Generate the code that will decrypt and execute the payload and randomly select one.
    $BaseScriptArray2  = @()
    $BaseScriptArray2 += '(' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript1 + ' '*(Get-Random -Input @(0,1)) + ").$Trim(" + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar '" + ' '*(Get-Random -Input @(0,1)) + ").$SplitMethod2(" + ' '*(Get-Random -Input @(0,1)) + "'" + $DigitDelimiterChar + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray2 += "`[$CharStr[]]" + ' '*(Get-Random -Input @(0,1)) + "[$Int[]]" + ' '*(Get-Random -Input @(0,1)) + "(" + ' '*(Get-Random -Input @(0,1)) + $NewScript1 + ' '*(Get-Random -Input @(0,1)) + ").$Trim(" + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar '" + ' '*(Get-Random -Input @(0,1)) + ").$SplitMethod2(" + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar'" + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray2  = (Get-Random -Input $BaseScriptArray2)
    
    # Generate random JOIN syntax for all above options.
    $NewScriptArray2   = @()
    $NewScriptArray2  += $BaseScriptArray2 + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray2  += $Join + ' '*(Get-Random -Input @(0,1)) + '(' + $BaseScriptArray2 + ')'
    $NewScriptArray2  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $BaseScriptArray2 + ' '*(Get-Random -Input @(0,1)) + ')'
    
    # Randomly select one of the above commands.
    $NewScript = (Get-Random -Input $NewScriptArray2)
    
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
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Insert)"         , "''.Insert.ToString()"))         + '[' + (Get-Random -Input @(3,7,14,23,33)) + ',' + (Get-Random -Input @(10,26,41)) + ",27]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Normalize)"      , "''.Normalize.ToString()"))      + '[' + (Get-Random -Input @(3,13,23,33,55,59,77)) + ',' + (Get-Random -Input @(15,35,41,45)) + ",46]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Chars)"          , "''.Chars.ToString()"))          + '[' + (Get-Random -Input @(11,15)) + ',' + (Get-Random -Input @(18,24)) + ",19]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.SubString)"      , "''.SubString.ToString()"))      + '[' + (Get-Random -Input @(3,13,17,26,37,47,51,60,67)) + ',' + (Get-Random -Input @(29,63,72)) + ',' + (Get-Random -Input @(30,64)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Remove)"         , "''.Remove.ToString()"))         + '[' + (Get-Random -Input @(3,14,23,30,45,56,65)) + ',' + (Get-Random -Input @(8,12,26,50,54,68)) + ',' + (Get-Random -Input @(27,69)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.LastIndexOfAny)" , "''.LastIndexOfAny.ToString()")) + '[' + (Get-Random -Input @(0,8,34,42,67,76,84,92,117,126,133)) + ',' + (Get-Random -Input @(11,45,79,95,129)) + ',' + (Get-Random -Input @(12,46,80,96,130)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.LastIndexOf)"    , "''.LastIndexOf.ToString()"))    + '[' + (Get-Random -Input @(0,8,29,37,57,66,74,82,102,111,118,130,138,149,161,169,180,191,200,208,216,227,238,247,254,266,274,285,306,315,326,337,345,356,367,376,393,402,413,424,432,443,454,463,470,491,500,511)) + ',' + (Get-Random -Input @(11,25,40,54,69,85,99,114,141,157,172,188,203,219,235,250,277,293,300,333,348,364,379,387,420,435,451,466,485,518)) + ',' + (Get-Random -Input @(12,41,70,86,115,142,173,204,220,251,278,349,380,436,467)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.IsNormalized)"   , "''.IsNormalized.ToString()"))   + '[' + (Get-Random -Input @(5,13,26,34,57,61,75,79)) + ',' + (Get-Random -Input @(15,36,43,47)) + ",48]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.IndexOfAny)"     , "''.IndexOfAny.ToString()"))     + '[' + (Get-Random -Input @(0,4,30,34,59,68,76,80,105,114,121)) + ',' + (Get-Random -Input @(7,37,71,83,117)) + ',' + (Get-Random -Input @(8,38,72,84,118)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.IndexOf)"        , "''.IndexOf.ToString()"))        + '[' + (Get-Random -Input @(0,4,25,29,49,58,66,70,90,99,106,118,122,133,145,149,160,171,180,188,192,203,214,223,230,242,246,257,278,287,298,309,313,324,335,344,361,370,381,392,396,407,418,427,434,455,464,475)) + ',' + (Get-Random -Input @(7,21,32,46,61,73,87,102,125,141,152,168,183,195,211,226,249,265,272,305,316,332,347,355,388,399,415,430,449,482)) + ',' + (Get-Random -Input @(8,33,62,74,103,126,153,184,196,227,250,317,348,400,431)) + "]-Join''" + ")"
    # Commenting below option since $env:Public differs in string value for non-English operating systems.
    #$InvokeExpressionSyntax += $InvocationOperator + "( `$env:Public[13]+`$env:Public[5]+'x')"

    # Randomly choose from above invoke operation syntaxes.
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)

    # Randomize the case of selected invoke operation.
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    
    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    
    # Randomly choose from above invoke operation syntaxes.
    $NewScript = (Get-Random -Input $InvokeOptions)
    
    # Reassemble all components of the final command.
    $NewScript = $ScriptStringPart1 + $NewScript + '}'
    
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