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



Function Invoke-Obfuscation
{
<#
.SYNOPSIS

Master function that orchestrates the application of all obfuscation functions to provided PowerShell script block or script path contents. Interactive mode enables one to explore all available obfuscation functions and apply them incrementally to input PowerShell script block or script path contents.

Invoke-Obfuscation Function: Invoke-Obfuscation
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Show-AsciiArt, Show-HelpMenu, Show-Menu, Show-OptionsMenu, Show-Tutorial and Out-ScriptContents (all located in Invoke-Obfuscation.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Invoke-Obfuscation orchestrates the application of all obfuscation functions to provided PowerShell script block or script path contents to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments and common parent-child process relationships.

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER ScriptPath

Specifies the path to your payload (can be local file, UNC-path, or remote URI).

.PARAMETER Command

Specifies the obfuscation commands to run against the input ScriptBlock or ScriptPath parameter.

.PARAMETER NoExit

(Optional - only works if Command is specified) Outputs the option to not exit after running obfuscation commands defined in Command parameter.

.PARAMETER Quiet

(Optional - only works if Command is specified) Outputs the option to output only the final obfuscated result via stdout.

.EXAMPLE

C:\PS> Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation

C:\PS> Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green}

C:\PS> Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -Command 'TOKEN\ALL\1,1,TEST,LAUNCHER\STDIN++\2347,CLIP'

C:\PS> Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -Command 'TOKEN\ALL\1,1,TEST,LAUNCHER\STDIN++\2347,CLIP' -NoExit

C:\PS> Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -Command 'TOKEN\ALL\1,1,TEST,LAUNCHER\STDIN++\2347,CLIP' -Quiet

C:\PS> Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -Command 'TOKEN\ALL\1,1,TEST,LAUNCHER\STDIN++\2347,CLIP' -NoExit -Quiet

.NOTES

Invoke-Obfuscation orchestrates the application of all obfuscation functions to provided PowerShell script block or script path contents to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'ScriptPath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptPath,
        
        [String]
        $Command,
        
        [Switch]
        $NoExit,
        
        [Switch]
        $Quiet
    )

    # Define variables for CLI functionality.
    $Script:CliCommands       = @()
    $Script:CompoundCommand   = @()
    $Script:QuietWasSpecified = $FALSE
    $CliWasSpecified          = $FALSE
    $NoExitWasSpecified       = $FALSE

    # Either convert ScriptBlock to a String or convert script at $Path to a String.
    If($PSBoundParameters['ScriptBlock'])
    {
        $Script:CliCommands += ('set scriptblock ' + [String]$ScriptBlock)
    }
    If($PSBoundParameters['ScriptPath'])
    {
        $Script:CliCommands += ('set scriptpath ' + $ScriptPath)
    }

    # Append Command to CliCommands if specified by user input.
    If($PSBoundParameters['Command'])
    {
        $Script:CliCommands += $Command.Split(',')
        $CliWasSpecified = $TRUE

        If($PSBoundParameters['NoExit'])
        {
            $NoExitWasSpecified = $TRUE
        }

        If($PSBoundParameters['Quiet'])
        {
            # Create empty Write-Host and Start-Sleep proxy functions to cause any Write-Host or Start-Sleep invocations to not do anything until non-interactive -Command values are finished being processed.
            Function Write-Host {}
            Function Start-Sleep {}
            $Script:QuietWasSpecified = $TRUE
        }
    }

    ########################################
    ## Script-wide variable instantiation ##
    ########################################

    # Script-level array of Show Options menu, set as SCRIPT-level so it can be set from within any of the functions.
    # Build out menu for Show Options selection from user in Show-OptionsMenu menu.
    $Script:ScriptPath   = ''
    $Script:ScriptBlock  = ''
    $Script:CliSyntax         = @()
    $Script:ExecutionCommands = @()
    $Script:ObfuscatedCommand = ''
    $Script:ObfuscatedCommandHistory = @()
    $Script:ObfuscationLength = ''
    $Script:OptionsMenu =   @()
    $Script:OptionsMenu += , @('ScriptPath '       , $Script:ScriptPath       , $TRUE)
    $Script:OptionsMenu += , @('ScriptBlock'       , $Script:ScriptBlock      , $TRUE)
    $Script:OptionsMenu += , @('CommandLineSyntax' , $Script:CliSyntax        , $FALSE)
    $Script:OptionsMenu += , @('ExecutionCommands' , $Script:ExecutionCommands, $FALSE)
    $Script:OptionsMenu += , @('ObfuscatedCommand' , $Script:ObfuscatedCommand, $FALSE)
    $Script:OptionsMenu += , @('ObfuscationLength' , $Script:ObfuscatedCommand, $FALSE)
    # Build out $SetInputOptions from above items set as $TRUE (as settable).
    $SettableInputOptions = @()
    ForEach($Option in $Script:OptionsMenu)
    {
        If($Option[2]) {$SettableInputOptions += ([String]$Option[0]).ToLower().Trim()}
    }

    # Script-level variable for whether LAUNCHER has been applied to current ObfuscatedToken.
    $Script:LauncherApplied = $FALSE

    # Ensure Invoke-Obfuscation module was properly imported before continuing.
    If(!(Get-Module Invoke-Obfuscation | Where-Object {$_.ModuleType -eq 'Manifest'}))
    {
        $PathTopsd1 = "$ScriptDir\Invoke-Obfuscation.psd1"
        If($PathTopsd1.Contains(' ')) {$PathTopsd1 = '"' + $PathTopsd1 + '"'}
        Write-Host "`n`nERROR: Invoke-Obfuscation module is not loaded. You must run:" -ForegroundColor Red
        Write-Host "       Import-Module $PathTopsd1`n`n" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        Exit
    }

    # Maximum size for cmd.exe and clipboard.
    $CmdMaxLength = 8190
    
    # Build interactive menus.
    $LineSpacing = '[*] '
    
    # Main Menu.
    $MenuLevel =   @()
    $MenuLevel+= , @($LineSpacing, 'TOKEN'    , 'Obfuscate PowerShell command <Tokens>')
    $MenuLevel+= , @($LineSpacing, 'AST'      , "`tObfuscate PowerShell <Ast> nodes <(PS3.0+)>")    
    $MenuLevel+= , @($LineSpacing, 'STRING'   , 'Obfuscate entire command as a <String>')
    $MenuLevel+= , @($LineSpacing, 'ENCODING' , 'Obfuscate entire command via <Encoding>')
    $MenuLevel+= , @($LineSpacing, 'COMPRESS'       , 'Convert entire command to one-liner and <Compress>')
    $MenuLevel+= , @($LineSpacing, 'LAUNCHER'       , 'Obfuscate command args w/<Launcher> techniques (run once at end)')
    
    # Main\Token Menu.
    $MenuLevel_Token                 =   @()
    $MenuLevel_Token                += , @($LineSpacing, 'STRING'     , 'Obfuscate <String> tokens (suggested to run first)')
    $MenuLevel_Token                += , @($LineSpacing, 'COMMAND'    , 'Obfuscate <Command> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'ARGUMENT'   , 'Obfuscate <Argument> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'MEMBER'     , 'Obfuscate <Member> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'VARIABLE'   , 'Obfuscate <Variable> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'TYPE  '     , 'Obfuscate <Type> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'COMMENT'    , 'Remove all <Comment> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'WHITESPACE' , 'Insert random <Whitespace> (suggested to run last)')
    $MenuLevel_Token                += , @($LineSpacing, 'ALL   '     , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Token_String          =   @()
    $MenuLevel_Token_String         += , @($LineSpacing, '1' , "Concatenate --> e.g. <('co'+'ffe'+'e')>"                           , @('Out-ObfuscatedTokenCommand', 'String', 1))
    $MenuLevel_Token_String         += , @($LineSpacing, '2' , "Reorder     --> e.g. <('{1}{0}'-f'ffee','co')>"                    , @('Out-ObfuscatedTokenCommand', 'String', 2))
    
    $MenuLevel_Token_Command         =   @()
    $MenuLevel_Token_Command        += , @($LineSpacing, '1' , 'Ticks                   --> e.g. <Ne`w-O`Bject>'                   , @('Out-ObfuscatedTokenCommand', 'Command', 1))
    $MenuLevel_Token_Command        += , @($LineSpacing, '2' , "Splatting + Concatenate --> e.g. <&('Ne'+'w-Ob'+'ject')>"          , @('Out-ObfuscatedTokenCommand', 'Command', 2))
    $MenuLevel_Token_Command        += , @($LineSpacing, '3' , "Splatting + Reorder     --> e.g. <&('{1}{0}'-f'bject','New-O')>"   , @('Out-ObfuscatedTokenCommand', 'Command', 3))
    
    $MenuLevel_Token_Argument        =   @()
    $MenuLevel_Token_Argument       += , @($LineSpacing, '1' , 'Random Case --> e.g. <nEt.weBclIenT>'                              , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 1))
    $MenuLevel_Token_Argument       += , @($LineSpacing, '2' , 'Ticks       --> e.g. <nE`T.we`Bc`lIe`NT>'                          , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 2))
    $MenuLevel_Token_Argument       += , @($LineSpacing, '3' , "Concatenate --> e.g. <('Ne'+'t.We'+'bClient')>"                    , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 3))
    $MenuLevel_Token_Argument       += , @($LineSpacing, '4' , "Reorder     --> e.g. <('{1}{0}'-f'bClient','Net.We')>"             , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 4))
    
    $MenuLevel_Token_Member          =   @()
    $MenuLevel_Token_Member         += , @($LineSpacing, '1' , 'Random Case --> e.g. <dOwnLoAdsTRing>'                             , @('Out-ObfuscatedTokenCommand', 'Member', 1))
    $MenuLevel_Token_Member         += , @($LineSpacing, '2' , 'Ticks       --> e.g. <d`Ow`NLoAd`STRin`g>'                         , @('Out-ObfuscatedTokenCommand', 'Member', 2))
    $MenuLevel_Token_Member         += , @($LineSpacing, '3' , "Concatenate --> e.g. <('dOwnLo'+'AdsT'+'Ring').Invoke()>"          , @('Out-ObfuscatedTokenCommand', 'Member', 3))
    $MenuLevel_Token_Member         += , @($LineSpacing, '4' , "Reorder     --> e.g. <('{1}{0}'-f'dString','Downloa').Invoke()>"   , @('Out-ObfuscatedTokenCommand', 'Member', 4))
    
    $MenuLevel_Token_Variable        =   @()
    $MenuLevel_Token_Variable       += , @($LineSpacing, '1' , 'Random Case + {} + Ticks --> e.g. <${c`hEm`eX}>'                   , @('Out-ObfuscatedTokenCommand', 'Variable', 1))
    
    $MenuLevel_Token_Type            =   @()
    $MenuLevel_Token_Type           += , @($LineSpacing, '1' , "Type Cast + Concatenate --> e.g. <[Type]('Con'+'sole')>"           , @('Out-ObfuscatedTokenCommand', 'Type', 1))
    $MenuLevel_Token_Type           += , @($LineSpacing, '2' , "Type Cast + Reordered   --> e.g. <[Type]('{1}{0}'-f'sole','Con')>" , @('Out-ObfuscatedTokenCommand', 'Type', 2))
    
    $MenuLevel_Token_Whitespace      =   @()
    $MenuLevel_Token_Whitespace     += , @($LineSpacing, '1' , "`tRandom Whitespace --> e.g. <.( 'Ne'  +'w-Ob' +  'ject')>"        , @('Out-ObfuscatedTokenCommand', 'RandomWhitespace', 1))
    
    $MenuLevel_Token_Comment         =   @()
    $MenuLevel_Token_Comment        += , @($LineSpacing, '1' , "Remove Comments   --> e.g. self-explanatory"                       , @('Out-ObfuscatedTokenCommand', 'Comment', 1))

    $MenuLevel_Token_All             =   @()
    $MenuLevel_Token_All            += , @($LineSpacing, '1' , "`tExecute <ALL> Token obfuscation techniques (random order)"       , @('Out-ObfuscatedTokenCommandAll', '', ''))
    
    # Main\Token Menu.
    $MenuLevel_Ast                            =   @()
    $MenuLevel_Ast                           += , @($LineSpacing, 'NamedAttributeArgumentAst' , 'Obfuscate <NamedAttributeArgumentAst> nodes')
    $MenuLevel_Ast                           += , @($LineSpacing, 'ParamBlockAst'             , "`t`tObfuscate <ParamBlockAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'ScriptBlockAst'            , "`t`tObfuscate <ScriptBlockAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'AttributeAst'              , "`t`tObfuscate <AttributeAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'BinaryExpressionAst'       , "`tObfuscate <BinaryExpressionAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'HashtableAst'              , "`t`tObfuscate <HashtableAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'CommandAst'                , "`t`tObfuscate <CommandAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'AssignmentStatementAst'    , "`tObfuscate <AssignmentStatementAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'TypeExpressionAst'         , "`tObfuscate <TypeExpressionAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'TypeConstraintAst'         , "`tObfuscate <TypeConstraintAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'ALL'                       , "`t`t`tSelect <All> choices from above")
    
    $MenuLevel_Ast_NamedAttributeArgumentAst  =   @()
    $MenuLevel_Ast_NamedAttributeArgumentAst += , @($LineSpacing, '1' , 'Reorder e.g. <[Parameter(Mandatory, ValueFromPipeline = $True)]> --> <[Parameter(Mandatory = $True, ValueFromPipeline)]>'                     , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.NamedAttributeArgumentAst'), 1))

    $MenuLevel_Ast_ParamBlockAst              =   @()
    $MenuLevel_Ast_ParamBlockAst             += , @($LineSpacing, '1' , 'Reorder e.g. <Param([Int]$One, [Int]$Two)> --> <Param([Int]$Two, [Int]$One)>'                                                                 , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.ParamBlockAst'), 1))

    $MenuLevel_Ast_ScriptBlockAst             =   @()
    $MenuLevel_Ast_ScriptBlockAst            += , @($LineSpacing, '1' , 'Reorder e.g. <{ Begin {} Process {} End {} }> --> <{ End {} Begin {} Process {} }>'                                                           , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.ScriptBlockAst'), 1))

    $MenuLevel_Ast_AttributeAst               =   @()
    $MenuLevel_Ast_AttributeAst              += , @($LineSpacing, '1' , 'Reorder e.g. <[Parameter(Position = 0, Mandatory)]> --> <[Parameter(Mandatory, Position = 0)]>'                                               , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.AttributeAst'), 1))

    $MenuLevel_Ast_BinaryExpressionAst        =   @()
    $MenuLevel_Ast_BinaryExpressionAst       += , @($LineSpacing, '1' , 'Reorder e.g. <(2 + 3) * 4> --> <4 * (3 + 2)>'                                                                                                 , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.BinaryExpressionAst'), 1))
    
    $MenuLevel_Ast_HashtableAst               =   @()
    $MenuLevel_Ast_HashtableAst              += , @($LineSpacing, '1' , "Reorder e.g. <@{ProviderName = 'Microsoft-Windows-PowerShell'; Id = 4104}> --> <@{Id = 4104; ProviderName = 'Microsoft-Windows-PowerShell'}>" , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.HashtableAst'), 1))

    $MenuLevel_Ast_CommandAst                 =   @()
    $MenuLevel_Ast_CommandAst                += , @($LineSpacing, '1' , 'Reorder e.g. <Get-Random -Min 1 -Max 100> --> <Get-Random -Max 100 -Min 1>'                                                                   , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.CommandAst'), 1))
    
    $MenuLevel_Ast_AssignmentStatementAst     =   @()
    $MenuLevel_Ast_AssignmentStatementAst    += , @($LineSpacing, '1' , 'Rename e.g. <$Example = "Example"> --> <Set-Variable -Name Example -Value ("Example")>'                                                       , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.AssignmentStatementAst'), 1))
    
    $MenuLevel_Ast_TypeExpressionAst          =   @()
    $MenuLevel_Ast_TypeExpressionAst         += , @($LineSpacing, '1' , 'Rename e.g. <[ScriptBlock]> --> <[Management.Automation.ScriptBlock]>'                                                                        , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.TypeExpressionAst'), 1))

    $MenuLevel_Ast_TypeConstraintAst          =   @()
    $MenuLevel_Ast_TypeConstraintAst         += , @($LineSpacing, '1' , 'Rename e.g. <[Int] $Integer = 1> --> <[System.Int32] $Integer = 1>'                                                                             , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.TypeConstraintAst'), 1))

    $MenuLevel_Ast_All                        =   @()
    $MenuLevel_Ast_All                       += , @($LineSpacing, '1' , "`tExecute <ALL> Ast obfuscation techniques"                                                                                                   , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'), ''))
    
    # Main\String Menu.
    $MenuLevel_String                =   @()
    $MenuLevel_String               += , @($LineSpacing, '1' , '<Concatenate> entire command'                                      , @('Out-ObfuscatedStringCommand', '', 1))
    $MenuLevel_String               += , @($LineSpacing, '2' , '<Reorder> entire command after concatenating'                      , @('Out-ObfuscatedStringCommand', '', 2))
    $MenuLevel_String               += , @($LineSpacing, '3' , '<Reverse> entire command after concatenating'                      , @('Out-ObfuscatedStringCommand', '', 3))

    # Main\Encoding Menu.
    $MenuLevel_Encoding              =   @()
    $MenuLevel_Encoding             += , @($LineSpacing, '1' , "`tEncode entire command as <ASCII>"                                , @('Out-EncodedAsciiCommand'           , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '2' , "`tEncode entire command as <Hex>"                                  , @('Out-EncodedHexCommand'             , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '3' , "`tEncode entire command as <Octal>"                                , @('Out-EncodedOctalCommand'           , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '4' , "`tEncode entire command as <Binary>"                               , @('Out-EncodedBinaryCommand'          , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '5' , "`tEncrypt entire command as <SecureString> (AES)"                  , @('Out-SecureStringCommand'           , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '6' , "`tEncode entire command as <BXOR>"                                 , @('Out-EncodedBXORCommand'            , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '7' , "`tEncode entire command as <Special Characters>"                   , @('Out-EncodedSpecialCharOnlyCommand' , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '8' , "`tEncode entire command as <Whitespace>"                           , @('Out-EncodedWhitespaceCommand'      , '', ''))

    # Main\Compress Menu.
    $MenuLevel_Compress              =   @()
    $MenuLevel_Compress             += , @($LineSpacing, '1' , "Convert entire command to one-liner and <compress>"                , @('Out-CompressedCommand'             , '', ''))
    
    # Main\Launcher Menu.
    $MenuLevel_Launcher              =   @()
    $MenuLevel_Launcher             += , @($LineSpacing, 'PS'            , "`t<PowerShell>")
    $MenuLevel_Launcher             += , @($LineSpacing, 'CMD'           , '<Cmd> + PowerShell')
    $MenuLevel_Launcher             += , @($LineSpacing, 'WMIC'          , '<Wmic> + PowerShell')
    $MenuLevel_Launcher             += , @($LineSpacing, 'RUNDLL'        , '<Rundll32> + PowerShell')
    $MenuLevel_Launcher             += , @($LineSpacing, 'VAR+'          , 'Cmd + set <Var> && PowerShell iex <Var>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'STDIN+'        , 'Cmd + <Echo> | PowerShell - (stdin)')
    $MenuLevel_Launcher             += , @($LineSpacing, 'CLIP+'         , 'Cmd + <Echo> | Clip && PowerShell iex <clipboard>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'VAR++'         , 'Cmd + set <Var> && Cmd && PowerShell iex <Var>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'STDIN++'       , 'Cmd + set <Var> && Cmd <Echo> | PowerShell - (stdin)')
    $MenuLevel_Launcher             += , @($LineSpacing, 'CLIP++'        , 'Cmd + <Echo> | Clip && Cmd && PowerShell iex <clipboard>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'RUNDLL++'      , 'Cmd + set Var && <Rundll32> && PowerShell iex Var')
    $MenuLevel_Launcher             += , @($LineSpacing, 'MSHTA++'       , 'Cmd + set Var && <Mshta> && PowerShell iex Var')

    $MenuLevel_Launcher_PS           =   @()
    $MenuLevel_Launcher_PS          += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '1'))

    $MenuLevel_Launcher_CMD          =   @()
    $MenuLevel_Launcher_CMD         += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '2'))

    $MenuLevel_Launcher_WMIC         =   @()
    $MenuLevel_Launcher_WMIC        += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '3'))

    $MenuLevel_Launcher_RUNDLL       =   @()
    $MenuLevel_Launcher_RUNDLL      += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '4'))

    ${MenuLevel_Launcher_VAR+}       =   @()
    ${MenuLevel_Launcher_VAR+}      += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '5'))

    ${MenuLevel_Launcher_STDIN+}     =   @()
    ${MenuLevel_Launcher_STDIN+}    += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '6'))
    
    ${MenuLevel_Launcher_CLIP+}      =   @()
    ${MenuLevel_Launcher_CLIP+}     += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '7'))
    
    ${MenuLevel_Launcher_VAR++}      =   @()
    ${MenuLevel_Launcher_VAR++}     += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '8'))

    ${MenuLevel_Launcher_STDIN++}    =   @()
    ${MenuLevel_Launcher_STDIN++}   += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '0' , "`tNO EXECUTION FLAGS"                                        , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '1' , "`t-NoExit"                                                   , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '2' , "`t-NonInteractive"                                           , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '3' , "`t-NoLogo"                                                   , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '4' , "`t-NoProfile"                                                , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '5' , "`t-Command"                                                  , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '6' , "`t-WindowStyle Hidden"                                       , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '7' , "`t-ExecutionPolicy Bypass"                                   , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '8' , "`t-Wow64 (to path 32-bit powershell.exe)"                    , @('Out-PowerShellLauncher', '', '9'))

    ${MenuLevel_Launcher_CLIP++}     =   @()
    ${MenuLevel_Launcher_CLIP++}    += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '10'))

    ${MenuLevel_Launcher_RUNDLL++}   =   @()
    ${MenuLevel_Launcher_RUNDLL++}  += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '11'))

    ${MenuLevel_Launcher_MSHTA++}    =   @()
    ${MenuLevel_Launcher_MSHTA++}   += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '12'))

    # Input options to display non-interactive menus or perform actions.
    $TutorialInputOptions         = @(@('tutorial')                            , "<Tutorial> of how to use this tool        `t  " )
    $MenuInputOptionsShowHelp     = @(@('help','get-help','?','-?','/?','menu'), "Show this <Help> Menu                     `t  " )
    $MenuInputOptionsShowOptions  = @(@('show options','show','options')       , "<Show options> for payload to obfuscate   `t  " )
    $ClearScreenInputOptions      = @(@('clear','clear-host','cls')            , "<Clear> screen                            `t  " )
    $CopyToClipboardInputOptions  = @(@('copy','clip','clipboard')             , "<Copy> ObfuscatedCommand to clipboard     `t  " )
    $OutputToDiskInputOptions     = @(@('out')                                 , "Write ObfuscatedCommand <Out> to disk     `t  " )
    $ExecutionInputOptions        = @(@('exec','execute','test','run')         , "<Execute> ObfuscatedCommand locally       `t  " )
    $ResetObfuscationInputOptions = @(@('reset')                               , "<Reset> ALL obfuscation for ObfuscatedCommand  ")
    $UndoObfuscationInputOptions  = @(@('undo')                                , "<Undo> LAST obfuscation for ObfuscatedCommand  ")
    $BackCommandInputOptions      = @(@('back','cd ..')                        , "Go <Back> to previous obfuscation menu    `t  " )
    $ExitCommandInputOptions      = @(@('quit','exit')                         , "<Quit> Invoke-Obfuscation                 `t  " )
    $HomeMenuInputOptions         = @(@('home','main')                         , "Return to <Home> Menu                     `t  " )
    # For Version 1.0 ASCII art is not necessary.
    #$ShowAsciiArtInputOptions     = @(@('ascii')                               , "Display random <ASCII> art for the lulz :)`t")
    
    # Add all above input options lists to be displayed in SHOW OPTIONS menu.
    $AllAvailableInputOptionsLists   = @()
    $AllAvailableInputOptionsLists  += , $TutorialInputOptions
    $AllAvailableInputOptionsLists  += , $MenuInputOptionsShowHelp
    $AllAvailableInputOptionsLists  += , $MenuInputOptionsShowOptions
    $AllAvailableInputOptionsLists  += , $ClearScreenInputOptions
    $AllAvailableInputOptionsLists  += , $ExecutionInputOptions
    $AllAvailableInputOptionsLists  += , $CopyToClipboardInputOptions
    $AllAvailableInputOptionsLists  += , $OutputToDiskInputOptions
    $AllAvailableInputOptionsLists  += , $ResetObfuscationInputOptions
    $AllAvailableInputOptionsLists  += , $UndoObfuscationInputOptions
    $AllAvailableInputOptionsLists  += , $BackCommandInputOptions    
    $AllAvailableInputOptionsLists  += , $ExitCommandInputOptions
    $AllAvailableInputOptionsLists  += , $HomeMenuInputOptions
    # For Version 1.0 ASCII art is not necessary.
    #$AllAvailableInputOptionsLists  += , $ShowAsciiArtInputOptions

    # Input options to change interactive menus.
    $ExitInputOptions = $ExitCommandInputOptions[0]
    $MenuInputOptions = $BackCommandInputOptions[0]
    
    # Obligatory ASCII Art.
    Show-AsciiArt
    Start-Sleep -Seconds 2
    
    # Show Help Menu once at beginning of script.
    Show-HelpMenu
    
    # Main loop for user interaction. Show-Menu function displays current function along with acceptable input options (defined in arrays instantiated above).
    # User input and validation is handled within Show-Menu.
    $UserResponse = ''
    While($ExitInputOptions -NotContains ([String]$UserResponse).ToLower())
    {
        $UserResponse = ([String]$UserResponse).Trim()

        If($HomeMenuInputOptions[0] -Contains ([String]$UserResponse).ToLower())
        {
            $UserResponse = ''
        }

        # Display menu if it is defined in a menu variable with $UserResponse in the variable name.
        If(Test-Path ('Variable:' + "MenuLevel$UserResponse"))
        {
            $UserResponse = Show-Menu (Get-Variable "MenuLevel$UserResponse").Value $UserResponse $Script:OptionsMenu
        }
        Else
        {
            Write-Error "The variable MenuLevel$UserResponse does not exist."
            $UserResponse = 'quit'
        }
        
        If(($UserResponse -eq 'quit') -AND $CliWasSpecified -AND !$NoExitWasSpecified)
        {
            Write-Output $Script:ObfuscatedCommand.Trim("`n")
            $UserInput = 'quit'
        }
    }
}


# Get location of this script no matter what the current directory is for the process executing this script.
$ScriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 


Function Show-Menu
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays current menu with obfuscation navigation and application options for Invoke-Obfuscation.

Invoke-Obfuscation Function: Show-Menu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-Menu displays current menu with obfuscation navigation and application options for Invoke-Obfuscation.

.PARAMETER Menu

Specifies the menu options to display, with acceptable input options parsed out of this array.

.PARAMETER MenuName

Specifies the menu header display and the breadcrumb used in the interactive prompt display.

.PARAMETER Script:OptionsMenu

Specifies the script-wide variable containing additional acceptable input in addition to each menu's specific acceptable input (e.g. EXIT, QUIT, BACK, HOME, MAIN, etc.).

.EXAMPLE

C:\PS> Show-Menu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]
        $Menu,

        [String]
        $MenuName,

        [Object[]]
        $Script:OptionsMenu
    )

    # Extract all acceptable values from $Menu.
    $AcceptableInput = @()
    $SelectionContainsCommand = $FALSE
    ForEach($Line in $Menu)
    {
        # If there are 4 items in each $Line in $Menu then the fourth item is a command to exec if selected.
        If($Line.Count -eq 4)
        {
            $SelectionContainsCommand = $TRUE
        }
        $AcceptableInput += ($Line[1]).Trim(' ')
    }

    $UserInput = $NULL
    
    While($AcceptableInput -NotContains $UserInput)
    {
        # Format custom breadcrumb prompt.
        Write-Host "`n"
        $BreadCrumb = $MenuName.Trim('_')
        If($BreadCrumb.Length -gt 1)
        {
            If($BreadCrumb.ToLower() -eq 'show options')
            {
                $BreadCrumb = 'Show Options'
            }
            If($MenuName -ne '')
            {
                # Handle specific case substitutions from what is ALL CAPS in interactive menu and then correct casing we want to appear in the Breadcrumb.
                $BreadCrumbOCD  =   @()
                $BreadCrumbOCD += , @('ps'      ,'PS')
                $BreadCrumbOCD += , @('cmd'     ,'Cmd')
                $BreadCrumbOCD += , @('wmic'    ,'Wmic')
                $BreadCrumbOCD += , @('rundll'  ,'RunDll')
                $BreadCrumbOCD += , @('var+'    ,'Var+')
                $BreadCrumbOCD += , @('stdin+'  ,'StdIn+')
                $BreadCrumbOCD += , @('clip+'   ,'Clip+')
                $BreadCrumbOCD += , @('var++'   ,'Var++')
                $BreadCrumbOCD += , @('stdin++' ,'StdIn++')
                $BreadCrumbOCD += , @('clip++'  ,'Clip++')
                $BreadCrumbOCD += , @('rundll++','RunDll++')
                $BreadCrumbOCD += , @('mshta++' ,'Mshta++')
                $BreadCrumbOCD += , @('ast', 'AST')

                $BreadCrumbArray = @()
                ForEach($Crumb in $BreadCrumb.Split('_'))
                {
                    # Perform casing substitutions for any matches in $BreadCrumbOCD array.
                    $StillLookingForSubstitution = $TRUE
                    ForEach($Substitution in $BreadCrumbOCD)
                    {
                        If($Crumb.ToLower() -eq $Substitution[0])
                        {
                            $BreadCrumbArray += $Substitution[1]
                            $StillLookingForSubstitution = $FALSE
                        }
                    }

                    # If no substitution occurred above then simply upper-case the first character and lower-case all the remaining characters.
                    If($StillLookingForSubstitution)
                    {
                        $BreadCrumbArray += $Crumb.SubString(0,1).ToUpper() + $Crumb.SubString(1).ToLower()

                        # If no substitution was found for the 3rd or later BreadCrumb element (only for Launcher BreadCrumb) then throw a warning so we can add this substitution pair to $BreadCrumbOCD.
                        If(($BreadCrumb.Split('_').Count -eq 2) -AND ($BreadCrumb.StartsWith('Launcher_')) -AND ($Crumb -ne 'Launcher'))
                        {
                            Write-Warning "No substituion pair was found for `$Crumb=$Crumb in `$BreadCrumb=$BreadCrumb. Add this `$Crumb substitution pair to `$BreadCrumbOCD array in Invoke-Obfuscation."
                        }
                    }
                }
                $BreadCrumb = $BreadCrumbArray -Join '\'
            }
            $BreadCrumb = '\' + $BreadCrumb
        }
        
        # Output menu heading.
        $FirstLine = "Choose one of the below "
        If($BreadCrumb -ne '')
        {
            $FirstLine = $FirstLine + $BreadCrumb.Trim('\') + ' '
        }
        Write-Host "$FirstLine" -NoNewLine
        
        # Change color and verbiage if selection will execute command.
        If($SelectionContainsCommand)
        {
            Write-Host "options" -NoNewLine -ForegroundColor Green
            Write-Host " to" -NoNewLine
            Write-Host " APPLY" -NoNewLine -ForegroundColor Green
            Write-Host " to current payload" -NoNewLine
        }
        Else
        {
            Write-Host "options" -NoNewLine -ForegroundColor Yellow
        }
        Write-Host ":`n"
    
        ForEach($Line in $Menu)
        {
            $LineSpace  = $Line[0]
            $LineOption = $Line[1]
            $LineValue  = $Line[2]
            Write-Host $LineSpace -NoNewLine

            # If not empty then include breadcrumb in $LineOption output (is not colored and won't affect user input syntax).
            If(($BreadCrumb -ne '') -AND ($LineSpace.StartsWith('[')))
            {
                Write-Host ($BreadCrumb.ToUpper().Trim('\') + '\') -NoNewLine
            }
            
            # Change color if selection will execute command.
            If($SelectionContainsCommand)
            {
                Write-Host $LineOption -NoNewLine -ForegroundColor Green
            }
            Else
            {
                Write-Host $LineOption -NoNewLine -ForegroundColor Yellow
            }
            
            # Add additional coloring to string encapsulated by <> if it exists in $LineValue.
            If($LineValue.Contains('<') -AND $LineValue.Contains('>'))
            {
                $FirstPart  = $LineValue.SubString(0,$LineValue.IndexOf('<'))
                $MiddlePart = $LineValue.SubString($FirstPart.Length+1)
                $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
                $LastPart   = $LineValue.SubString($FirstPart.Length+$MiddlePart.Length+2)
                Write-Host "`t$FirstPart" -NoNewLine
                Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan

                # Handle if more than one term needs to be output in different color.
                If($LastPart.Contains('<') -AND $LastPart.Contains('>'))
                {
                    $LineValue  = $LastPart
                    $FirstPart  = $LineValue.SubString(0,$LineValue.IndexOf('<'))
                    $MiddlePart = $LineValue.SubString($FirstPart.Length+1)
                    $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
                    $LastPart   = $LineValue.SubString($FirstPart.Length+$MiddlePart.Length+2)
                    Write-Host "$FirstPart" -NoNewLine
                    If($MiddlePart.EndsWith("(PS3.0+)"))
                    {
                        Write-Host $MiddlePart -NoNewline -ForegroundColor Red
                    }
                    Else
                    {
                        Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
                    }
                }

                Write-Host $LastPart
            }
            Else
            {
                Write-Host "`t$LineValue"
            }
        }
        
        # Prompt for user input with custom breadcrumb prompt.
        Write-Host ''
        If($UserInput -ne '') {Write-Host ''}
        $UserInput = ''
        
        While(($UserInput -eq '') -AND ($Script:CompoundCommand.Count -eq 0))
        {
            # Output custom prompt.
            Write-Host "Invoke-Obfuscation$BreadCrumb> " -NoNewLine -ForegroundColor Magenta

            # Get interactive user input if CliCommands input variable was not specified by user.
            If(($Script:CliCommands.Count -gt 0) -OR ($Script:CliCommands -ne $NULL))
            {
                If($Script:CliCommands.GetType().Name -eq 'String')
                {
                    $NextCliCommand = $Script:CliCommands.Trim()
                    $Script:CliCommands = @()
                }
                Else
                {
                    $NextCliCommand = ([String]$Script:CliCommands[0]).Trim()
                    $Script:CliCommands = For($i=1; $i -lt $Script:CliCommands.Count; $i++) {$Script:CliCommands[$i]}
                }

                $UserInput = $NextCliCommand
            }
            Else
            {
                # If Command was defined on command line and NoExit switch was not defined then output final ObfuscatedCommand to stdout and then quit. Otherwise continue with interactive Invoke-Obfuscation.
                If($CliWasSpecified -AND ($Script:CliCommands.Count -lt 1) -AND ($Script:CompoundCommand.Count -lt 1) -AND ($Script:QuietWasSpecified -OR !$NoExitWasSpecified))
                {
                    If($Script:QuietWasSpecified)
                    {
                        # Remove Write-Host and Start-Sleep proxy functions so that Write-Host and Start-Sleep cmdlets will be called during the remainder of the interactive Invoke-Obfuscation session.
                        Remove-Item -Path Function:Write-Host
                        Remove-Item -Path Function:Start-Sleep

                        $Script:QuietWasSpecified = $FALSE

                        # Automatically run 'Show Options' so the user has context of what has successfully been executed.
                        $UserInput  = 'show options'
                        $BreadCrumb = 'Show Options'
                    }
                    # -NoExit wasn't specified and -Command was, so we will output the result back in the main While loop.
                    If(!$NoExitWasSpecified)
                    {
                        $UserInput = 'quit'
                    }
                }
                Else
                {
                    $UserInput = (Read-Host).Trim()
                }

                # Process interactive UserInput using CLI syntax, so comma-delimited and slash-delimited commands can be processed interactively.
                If(($Script:CliCommands.Count -eq 0) -AND !$UserInput.ToLower().StartsWith('set ') -AND $UserInput.Contains(','))
                {
                    $Script:CliCommands = $UserInput.Split(',')
                    
                    # Reset $UserInput so current While loop will be traversed once more and process UserInput command as a CliCommand.
                    $UserInput = ''
                }
            }
        }

        # Trim any leading trailing slashes so it doesn't misinterpret it as a compound command unnecessarily.
        $UserInput = $UserInput.Trim('/\')

        # Cause UserInput of base menu level directories to automatically work.
        # The only exception is STRING if the current MenuName is _token since it can be the base menu STRING or TOKEN/STRING.
        If((($MenuLevel | ForEach-Object {$_[1].Trim()}) -Contains $UserInput.Split('/\')[0]) -AND !(('string' -Contains $UserInput.Split('/\')[0]) -AND ($MenuName -eq '_token')) -AND ($MenuName -ne ''))
        {
            $UserInput = 'home/' + $UserInput.Trim()
        }

        # If current command contains \ or / and does not start with SET or OUT then we are dealing with a compound command.
        # Setting $Script:CompounCommand in below IF block.
        If(($Script:CompoundCommand.Count -eq 0) -AND !$UserInput.ToLower().StartsWith('set ') -AND !$UserInput.ToLower().StartsWith('out ') -AND ($UserInput.Contains('\') -OR $UserInput.Contains('/')))
        {
            $Script:CompoundCommand = $UserInput.Split('/\')
        }

        # If current command contains \ or / and does not start with SET then we are dealing with a compound command.
        # Parsing out next command from $Script:CompounCommand in below IF block.
        If($Script:CompoundCommand.Count -gt 0)
        {
            $UserInput = ''
            While(($UserInput -eq '') -AND ($Script:CompoundCommand.Count -gt 0))
            {
                # If last compound command then it will be a string.
                If($Script:CompoundCommand.GetType().Name -eq 'String')
                {
                    $NextCompoundCommand = $Script:CompoundCommand.Trim()
                    $Script:CompoundCommand = @()
                }
                Else
                {
                    # If there are more commands left in compound command then it won't be a string (above IF block).
                    # In this else block we get the next command from CompoundCommand array.
                    $NextCompoundCommand = ([String]$Script:CompoundCommand[0]).Trim()
                    
                    # Set remaining commands back into CompoundCommand.
                    $Temp = $Script:CompoundCommand
                    $Script:CompoundCommand = @()
                    For($i=1; $i -lt $Temp.Count; $i++)
                    {
                        $Script:CompoundCommand += $Temp[$i]
                    }
                }
                $UserInput = $NextCompoundCommand
            }
        }

        # Handle new RegEx functionality.
        # Identify if there is any regex in current UserInput by removing all alphanumeric characters (and + or # which are found in launcher names).
        $TempUserInput = $UserInput.ToLower()
        @(97..122) | ForEach-Object {$TempUserInput = $TempUserInput.Replace([String]([Char]$_),'')}
        @(0..9)    | ForEach-Object {$TempUserInput = $TempUserInput.Replace($_,'')}
        $TempUserInput = $TempUserInput.Replace(' ','').Replace('+','').Replace('#','').Replace('\','').Replace('/','').Replace('-','').Replace('?','')

        If(($TempUserInput.Length -gt 0) -AND !($UserInput.Trim().ToLower().StartsWith('set ')) -AND !($UserInput.Trim().ToLower().StartsWith('out ')))
        {
            # Replace any simple wildcard with .* syntax.
            $UserInput = $UserInput.Replace('.*','_____').Replace('*','.*').Replace('_____','.*')

            # Prepend UserInput with ^ and append with $ if not already there.
            If(!$UserInput.Trim().StartsWith('^') -AND !$UserInput.Trim().StartsWith('.*'))
            {
                $UserInput = '^' + $UserInput
            }
            If(!$UserInput.Trim().EndsWith('$') -AND !$UserInput.Trim().EndsWith('.*'))
            {
                $UserInput = $UserInput + '$'
            }

            # See if there are any filtered matches in the current menu.
            Try
            {
                $MenuFiltered = ($Menu | Where-Object {($_[1].Trim() -Match $UserInput) -AND ($_[1].Trim().Length -gt 0)} | ForEach-Object {$_[1].Trim()})
            }
            Catch
            {
                # Output error message if Regular Expression causes error in above filtering step.
                # E.g. Using *+ instead of *[+]
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host ' The current Regular Expression caused the following error:'
                write-host "       $_" -ForegroundColor Red
            }

            # If there are filtered matches in the current menu then randomly choose one for the UserInput value.
            If($MenuFiltered -ne $NULL)
            {
                # Randomly select UserInput from filtered options.
                $UserInput = (Get-Random -Input $MenuFiltered).Trim()

                # Output randomly chosen option (and filtered options selected from) if more than one option were returned from regex.
                If($MenuFiltered.Count -gt 1)
                {
                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    If($SelectionContainsCommand)
                    {
                        $ColorToOutput = 'Green'
                    }
                    Else
                    {
                        $ColorToOutput = 'Yellow'
                    }

                    Write-Host "`n`nRandomly selected " -NoNewline
                    Write-Host $UserInput -NoNewline -ForegroundColor $ColorToOutput
                    write-host " from the following filtered options: " -NoNewline

                    For($i=0; $i -lt $MenuFiltered.Count-1; $i++)
                    {
                        Write-Host $MenuFiltered[$i].Trim() -NoNewLine -ForegroundColor $ColorToOutput
                        Write-Host ', ' -NoNewLine
                    }
                    Write-Host $MenuFiltered[$MenuFiltered.Count-1].Trim() -NoNewLine -ForegroundColor $ColorToOutput
                }
            }
        }

        # If $UserInput is all numbers and is in a menu in $MenusWithMultiSelectNumbers
        $OverrideAcceptableInput = $FALSE
        $MenusWithMultiSelectNumbers = @('\Launcher')
        If(($UserInput.Trim(' 0123456789').Length -eq 0) -AND $BreadCrumb.Contains('\') -AND ($MenusWithMultiSelectNumbers -Contains $BreadCrumb.SubString(0,$BreadCrumb.LastIndexOf('\'))))
        {
            $OverrideAcceptableInput = $TRUE
        }
        
        If($ExitInputOptions -Contains $UserInput.ToLower())
        {
            Return $ExitInputOptions[0]
        }
        ElseIf($MenuInputOptions -Contains $UserInput.ToLower())
        {
            # Commands like 'back' that will return user to previous interactive menu.
            If($BreadCrumb.Contains('\')) {$UserInput = $BreadCrumb.SubString(0,$BreadCrumb.LastIndexOf('\')).Replace('\','_')}
            Else {$UserInput = ''}

            Return $UserInput.ToLower()
        }
        ElseIf($HomeMenuInputOptions[0] -Contains $UserInput.ToLower())
        {
            Return $UserInput.ToLower()
        }
        ElseIf($UserInput.ToLower().StartsWith('set '))
        {
            # Extract $UserInputOptionName and $UserInputOptionValue from $UserInput SET command.
            $UserInputOptionName  = $NULL
            $UserInputOptionValue = $NULL
            $HasError = $FALSE
    
            $UserInputMinusSet = $UserInput.SubString(4).Trim()
            If($UserInputMinusSet.IndexOf(' ') -eq -1)
            {
                $HasError = $TRUE
                $UserInputOptionName  = $UserInputMinusSet.Trim()
            }
            Else
            {
                $UserInputOptionName  = $UserInputMinusSet.SubString(0,$UserInputMinusSet.IndexOf(' ')).Trim().ToLower()
                $UserInputOptionValue = $UserInputMinusSet.SubString($UserInputMinusSet.IndexOf(' ')).Trim()
            }

            # Validate that $UserInputOptionName is defined in $SettableInputOptions.
            If($SettableInputOptions -Contains $UserInputOptionName)
            {
                # Perform separate validation for $UserInputOptionValue before setting value. Set to 'emptyvalue' if no value was entered.
                If($UserInputOptionValue.Length -eq 0) {$UserInputOptionName = 'emptyvalue'}
                Switch($UserInputOptionName.ToLower())
                {
                    'scriptpath' {
                        If($UserInputOptionValue -AND ((Test-Path $UserInputOptionValue) -OR ($UserInputOptionValue -Match '(http|https)://')))
                        {
                            # Reset ScriptBlock in case it contained a value.
                            $Script:ScriptBlock = ''
                        
                            # Check if user-input ScriptPath is a URL or a directory.
                            If($UserInputOptionValue -Match '(http|https)://')
                            {
                                # ScriptPath is a URL.
                            
                                # Download content.
                                $Script:ScriptBlock = (New-Object Net.WebClient).DownloadString($UserInputOptionValue)
                            
                                # Set script-wide variables for future reference.
                                $Script:ScriptPath                = $UserInputOptionValue
                                $Script:ObfuscatedCommand         = $Script:ScriptBlock
                                $Script:ObfuscatedCommandHistory  = @()
                                $Script:ObfuscatedCommandHistory += $Script:ScriptBlock
                                $Script:CliSyntax                 = @()
                                $Script:ExecutionCommands         = @()
                                $Script:LauncherApplied           = $FALSE
                            
                                Write-Host "`n`nSuccessfully set ScriptPath (as URL):" -ForegroundColor Cyan
                                Write-Host $Script:ScriptPath -ForegroundColor Magenta
                            }
                            ElseIf ((Get-Item $UserInputOptionValue) -is [System.IO.DirectoryInfo])
                            {
                                # ScriptPath does not exist.
                                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                                Write-Host ' Path is a directory instead of a file (' -NoNewLine
                                Write-Host "$UserInputOptionValue" -NoNewLine -ForegroundColor Cyan
                                Write-Host ").`n" -NoNewLine
                            }
                            Else
                            {
                                # Read contents from user-input ScriptPath value.
                                Get-ChildItem $UserInputOptionValue -ErrorAction Stop | Out-Null
                                $Script:ScriptBlock = [IO.File]::ReadAllText((Resolve-Path $UserInputOptionValue))
                        
                                # Set script-wide variables for future reference.
                                $Script:ScriptPath                = $UserInputOptionValue
                                $Script:ObfuscatedCommand         = $Script:ScriptBlock
                                $Script:ObfuscatedCommandHistory  = @()
                                $Script:ObfuscatedCommandHistory += $Script:ScriptBlock
                                $Script:CliSyntax                 = @()
                                $Script:ExecutionCommands         = @()
                                $Script:LauncherApplied           = $FALSE
                            
                                Write-Host "`n`nSuccessfully set ScriptPath:" -ForegroundColor Cyan
                                Write-Host $Script:ScriptPath -ForegroundColor Magenta
                            }
                        }
                        Else
                        {
                            # ScriptPath not found (failed Test-Path).
                            Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                            Write-Host ' Path not found (' -NoNewLine
                            Write-Host "$UserInputOptionValue" -NoNewLine -ForegroundColor Cyan
                            Write-Host ").`n" -NoNewLine
                        }
                    }
                    'scriptblock' {
                        # Remove evenly paired {} '' or "" if user includes it around their scriptblock input.
                        ForEach($Char in @(@('{','}'),@('"','"'),@("'","'")))
                        {
                            While($UserInputOptionValue.StartsWith($Char[0]) -AND $UserInputOptionValue.EndsWith($Char[1]))
                            {
                                $UserInputOptionValue = $UserInputOptionValue.SubString(1,$UserInputOptionValue.Length-2).Trim()
                            }
                        }

                        # Check if input is PowerShell encoded command syntax so we can decode for scriptblock.
                        If($UserInputOptionValue -Match 'powershell(.exe | )\s*-(e |ec |en |enc |enco |encod |encode)\s*["'']*[a-z=]')
                        {
                            # Extract encoded command.
                            $EncodedCommand = $UserInputOptionValue.SubString($UserInputOptionValue.ToLower().IndexOf(' -e')+3)
                            $EncodedCommand = $EncodedCommand.SubString($EncodedCommand.IndexOf(' ')).Trim(" '`"")

                            # Decode Unicode-encoded $EncodedCommand
                            $UserInputOptionValue = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedCommand))
                        }

                        # Set script-wide variables for future reference.
                        $Script:ScriptPath                = 'N/A'
                        $Script:ScriptBlock               = $UserInputOptionValue
                        $Script:ObfuscatedCommand         = $UserInputOptionValue
                        $Script:ObfuscatedCommandHistory  = @()
                        $Script:ObfuscatedCommandHistory += $UserInputOptionValue
                        $Script:CliSyntax                 = @()
                        $Script:ExecutionCommands         = @()
                        $Script:LauncherApplied           = $FALSE
                    
                        Write-Host "`n`nSuccessfully set ScriptBlock:" -ForegroundColor Cyan
                        Write-Host $Script:ScriptBlock -ForegroundColor Magenta
                    }
                    'emptyvalue' {
                        # No OPTIONVALUE was entered after OPTIONNAME.
                        $HasError = $TRUE
                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host ' No value was entered after' -NoNewLine
                        Write-Host ' SCRIPTBLOCK/SCRIPTPATH' -NoNewLine -ForegroundColor Cyan
                        Write-Host '.' -NoNewLine
                    }
                    default {Write-Error "An invalid OPTIONNAME ($UserInputOptionName) was passed to switch block."; Exit}
                }
            }
            Else
            {
                $HasError = $TRUE
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host ' OPTIONNAME' -NoNewLine
                Write-Host " $UserInputOptionName" -NoNewLine -ForegroundColor Cyan
                Write-Host " is not a settable option." -NoNewLine
            }
    
            If($HasError)
            {
                Write-Host "`n       Correct syntax is" -NoNewLine
                Write-Host ' SET OPTIONNAME VALUE' -NoNewLine -ForegroundColor Green
                Write-Host '.' -NoNewLine
        
                Write-Host "`n       Enter" -NoNewLine
                Write-Host ' SHOW OPTIONS' -NoNewLine -ForegroundColor Yellow
                Write-Host ' for more details.'
            }
        }
        ElseIf(($AcceptableInput -Contains $UserInput) -OR ($OverrideAcceptableInput))
        {
            # User input matches $AcceptableInput extracted from the current $Menu, so decide if:
            # 1) an obfuscation function needs to be called and remain in current interactive prompt, or
            # 2) return value to enter into a new interactive prompt.

            # Format breadcrumb trail to successfully retrieve the next interactive prompt.
            $UserInput = $BreadCrumb.Trim('\').Replace('\','_') + '_' + $UserInput
            If($BreadCrumb.StartsWith('\')) {$UserInput = '_' + $UserInput}

            # If the current selection contains a command to execute then continue. Otherwise return to go to another menu.
            If($SelectionContainsCommand)
            {
                # Make sure user has entered command or path to script.
                If($Script:ObfuscatedCommand -ne $NULL)
                {
                    # Iterate through lines in $Menu to extract command for the current selection in $UserInput.
                    ForEach($Line in $Menu)
                    {
                        If($Line[1].Trim(' ') -eq $UserInput.SubString($UserInput.LastIndexOf('_')+1)) {$CommandToExec = $Line[3]; Continue}
                    }

                    If(!$OverrideAcceptableInput)
                    {
                        # Extract arguments from $CommandToExec.
                        $Function = $CommandToExec[0]
                        $Token    = $CommandToExec[1]
                        $ObfLevel = $CommandToExec[2]
                    }
                    Else
                    {
                        # Overload above arguments if $OverrideAcceptableInput is $TRUE, and extract $Function from $BreadCrumb
                        Switch($BreadCrumb.ToLower())
                        {
                            '\launcher\ps'       {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 1}
                            '\launcher\cmd'      {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 2}
                            '\launcher\wmic'     {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 3}
                            '\launcher\rundll'   {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 4}
                            '\launcher\var+'     {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 5}
                            '\launcher\stdin+'   {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 6}
                            '\launcher\clip+'    {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 7}
                            '\launcher\var++'    {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 8}
                            '\launcher\stdin++'  {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 9}
                            '\launcher\clip++'   {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 10}
                            '\launcher\rundll++' {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 11}
                            '\launcher\mshta++'  {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 12}
                            default {Write-Error "An invalid value ($($BreadCrumb.ToLower())) was passed to switch block for setting `$Function when `$OverrideAcceptableInput -eq `$TRUE."; Exit}
                        }
                        # Extract $ObfLevel from first element in array (in case 0th element is used for informational purposes), and extract $Token from $BreadCrumb.
                        $ObfLevel = $Menu[1][3][2]
                        $Token = $UserInput.SubString($UserInput.LastIndexOf('_')+1)
                    }

                    # Convert ObfuscatedCommand (string) to ScriptBlock for next obfuscation function.
                    If(!($Script:LauncherApplied))
                    {
                        $ObfCommandScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Script:ObfuscatedCommand)
                    }
                    
                    # Validate that user has set SCRIPTPATH or SCRIPTBLOCK (by seeing if $Script:ObfuscatedCommand is empty).
                    If($Script:ObfuscatedCommand -eq '')
                    {
                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host " Cannot execute obfuscation commands without setting ScriptPath or ScriptBlock values in SHOW OPTIONS menu. Set these by executing" -NoNewLine
                        Write-Host ' SET SCRIPTBLOCK script_block_or_command' -NoNewLine -ForegroundColor Green
                        Write-Host ' or' -NoNewLine
                        Write-Host ' SET SCRIPTPATH path_to_script_or_URL' -NoNewLine -ForegroundColor Green
                        Write-Host '.'
                        Continue
                    }

                    # Save current ObfuscatedCommand to see if obfuscation was successful (i.e. no warnings prevented obfuscation from occurring).
                    $ObfuscatedCommandBefore = $Script:ObfuscatedCommand
                    $CmdToPrint = $NULL
                    If($Function -eq 'Out-ObfuscatedAst' -AND $PSVersionTable.PSVersion.Major -lt 3)
                    {
                        $AstPS3ErrorMessage = "AST obfuscation can only be used with PS3.0+. Update to PS3.0 or higher to use AST obfuscation."
                        If ($Script:QuietWasSpecified)
                        {
                            Write-Error $AstPS3ErrorMessage
                        }
                        Else
                        {
                            Write-Host "`n`nERROR: " -NoNewLine -ForegroundColor Red
                            Write-Host $AstPS3ErrorMessage -NoNewLine
                        }
                    }
                    ElseIf($Script:LauncherApplied)
                    {
                        If($Function -eq 'Out-PowerShellLauncher')
                        {
                            $ErrorMessage = ' You have already applied a launcher to ObfuscatedCommand.'
                        }
                        Else
                        {
                            $ErrorMessage = ' You cannot obfuscate after applying a Launcher to ObfuscatedCommand.'
                        }

                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host $ErrorMessage -NoNewLine
                        Write-Host "`n       Enter" -NoNewLine
                        Write-Host ' UNDO' -NoNewLine -ForegroundColor Yellow
                        Write-Host " to remove the launcher from ObfuscatedCommand.`n" -NoNewLine
                    }
                    Else
                    {
                        # Switch block to route to the correct function.
                        Switch($Function)
                        {
                            'Out-ObfuscatedTokenCommand'        {
                                $Script:ObfuscatedCommand = Out-ObfuscatedTokenCommand        -ScriptBlock $ObfCommandScriptBlock $Token $ObfLevel
                                $CmdToPrint = @("Out-ObfuscatedTokenCommand -ScriptBlock "," '$Token' $ObfLevel")
                            }
                            'Out-ObfuscatedTokenCommandAll'     {
                                $Script:ObfuscatedCommand = Out-ObfuscatedTokenCommand        -ScriptBlock $ObfCommandScriptBlock
                                $CmdToPrint = @("Out-ObfuscatedTokenCommand -ScriptBlock ","")
                            }
                            'Out-ObfuscatedAst'                 {
                                $Script:ObfuscatedCommand = Out-ObfuscatedAst                 -ScriptBlock $ObfCommandScriptBlock -AstTypesToObfuscate $Token
                                $CmdToPrint = @("Out-ObfuscatedAst -ScriptBlock ","")
                            }
                            'Out-ObfuscatedStringCommand'       {
                                $Script:ObfuscatedCommand = Out-ObfuscatedStringCommand       -ScriptBlock $ObfCommandScriptBlock $ObfLevel
                                $CmdToPrint = @("Out-ObfuscatedStringCommand -ScriptBlock "," $ObfLevel")
                            }
                            'Out-EncodedAsciiCommand'           {
                                $Script:ObfuscatedCommand = Out-EncodedAsciiCommand           -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedAsciiCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedHexCommand'             {
                                $Script:ObfuscatedCommand = Out-EncodedHexCommand             -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedHexCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedOctalCommand'           {
                                $Script:ObfuscatedCommand = Out-EncodedOctalCommand           -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedOctalCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedBinaryCommand'          {
                                $Script:ObfuscatedCommand = Out-EncodedBinaryCommand          -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedBinaryCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-SecureStringCommand'           {
                                $Script:ObfuscatedCommand = Out-SecureStringCommand           -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-SecureStringCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedBXORCommand'            {
                                $Script:ObfuscatedCommand = Out-EncodedBXORCommand            -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedBXORCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedSpecialCharOnlyCommand' {
                                $Script:ObfuscatedCommand = Out-EncodedSpecialCharOnlyCommand -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedSpecialCharOnlyCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedWhitespaceCommand' {
                                $Script:ObfuscatedCommand = Out-EncodedWhitespaceCommand      -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedWhitespaceCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-CompressedCommand' {
                                $Script:ObfuscatedCommand = Out-CompressedCommand             -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-CompressedCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-PowerShellLauncher'            {
                                # Extract numbers from string so we can output proper flag syntax in ExecutionCommands history.
                                $SwitchesAsStringArray = [char[]]$Token | Sort-Object -Unique | Where-Object {$_ -ne ' '}
                                
                                If($SwitchesAsStringArray -Contains '0')
                                {
                                    $CmdToPrint = @("Out-PowerShellLauncher -ScriptBlock "," $ObfLevel")
                                }
                                Else
                                {
                                    $HasWindowStyle = $FALSE
                                    $SwitchesToPrint = @()
                                    ForEach($Value in $SwitchesAsStringArray)
                                    {
                                        Switch($Value)
                                        {
                                            1 {$SwitchesToPrint += '-NoExit'}
                                            2 {$SwitchesToPrint += '-NonInteractive'}
                                            3 {$SwitchesToPrint += '-NoLogo'}
                                            4 {$SwitchesToPrint += '-NoProfile'}
                                            5 {$SwitchesToPrint += '-Command'}
                                            6 {If(!$HasWindowStyle) {$SwitchesToPrint += '-WindowStyle Hidden'; $HasWindowStyle = $TRUE}}
                                            7 {$SwitchesToPrint += '-ExecutionPolicy Bypass'}
                                            8 {$SwitchesToPrint += '-Wow64'}
                                            default {Write-Error "An invalid `$SwitchesAsString value ($Value) was passed to switch block."; Exit;}
                                        }
                                    }
                                    $SwitchesToPrint =  $SwitchesToPrint -Join ' '
                                    $CmdToPrint = @("Out-PowerShellLauncher -ScriptBlock "," $SwitchesToPrint $ObfLevel")
                                }
                                
                                $Script:ObfuscatedCommand = Out-PowerShellLauncher -ScriptBlock $ObfCommandScriptBlock -SwitchesAsString $Token $ObfLevel
                                
                                # Only set LauncherApplied to true if before/after are different (i.e. no warnings prevented launcher from being applied).
                                If($ObfuscatedCommandBefore -ne $Script:ObfuscatedCommand)
                                {
                                    $Script:LauncherApplied = $TRUE
                                }
                            }
                            default {Write-Error "An invalid `$Function value ($Function) was passed to switch block."; Exit;}
                        }

                        If(($Script:ObfuscatedCommand -ceq $ObfuscatedCommandBefore) -AND ($MenuName.StartsWith('_Token_')))
                        {
                            Write-Host "`nWARNING:" -NoNewLine -ForegroundColor Red
                            Write-Host " There were not any" -NoNewLine
                            If($BreadCrumb.SubString($BreadCrumb.LastIndexOf('\')+1).ToLower() -ne 'all') {Write-Host " $($BreadCrumb.SubString($BreadCrumb.LastIndexOf('\')+1))" -NoNewLine -ForegroundColor Yellow}
                            Write-Host " tokens to further obfuscate, so nothing changed."
                        }
                        Else
                        {
                            # Add to $Script:ObfuscatedCommandHistory if a change took place for the current ObfuscatedCommand.
                            $Script:ObfuscatedCommandHistory += , $Script:ObfuscatedCommand
    
                            # Convert UserInput to CLI syntax to store in CliSyntax variable if obfuscation occurred.
                            $CliSyntaxCurrentCommand = $UserInput.Trim('_ ').Replace('_','\')
    
                            # Add CLI command syntax to $Script:CliSyntax to maintain a history of commands to arrive at current obfuscated command for CLI syntax.
                            $Script:CliSyntax += $CliSyntaxCurrentCommand

                            # Add execution syntax to $Script:ExecutionCommands to maintain a history of commands to arrive at current obfuscated command.
                            $Script:ExecutionCommands += ($CmdToPrint[0] + '$ScriptBlock' + $CmdToPrint[1])

                            # Output syntax of CLI syntax and full command we executed in above Switch block.
                            Write-Host "`nExecuted:`t"
                            Write-Host "  CLI:  " -NoNewline
                            Write-Host $CliSyntaxCurrentCommand -ForegroundColor Cyan
                            Write-Host "  FULL: " -NoNewline
                            Write-Host $CmdToPrint[0] -NoNewLine -ForegroundColor Cyan
                            Write-Host '$ScriptBlock' -NoNewLine -ForegroundColor Magenta
                            Write-Host $CmdToPrint[1] -ForegroundColor Cyan

                            # Output obfuscation result.
                            Write-Host "`nResult:`t"
                            Out-ScriptContents $Script:ObfuscatedCommand -PrintWarning
                        }
                    }
                }
            }
            Else
            {
                Return $UserInput
            }
        }
        Else
        {
            If    ($MenuInputOptionsShowHelp[0]     -Contains $UserInput) {Show-HelpMenu}
            ElseIf($MenuInputOptionsShowOptions[0]  -Contains $UserInput) {Show-OptionsMenu}
            ElseIf($TutorialInputOptions[0]         -Contains $UserInput) {Show-Tutorial}
            ElseIf($ClearScreenInputOptions[0]      -Contains $UserInput) {Clear-Host}
            # For Version 1.0 ASCII art is not necessary.
            #ElseIf($ShowAsciiArtInputOptions[0]     -Contains $UserInput) {Show-AsciiArt -Random}
            ElseIf($ResetObfuscationInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCommand -ne $NULL) -AND ($Script:ObfuscatedCommand.Length -eq 0))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCommand has not been set. There is nothing to reset."
                }
                ElseIf($Script:ObfuscatedCommand -ceq $Script:ScriptBlock)
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCommand. There is nothing to reset."
                }
                Else
                {
                    $Script:LauncherApplied = $FALSE
                    $Script:ObfuscatedCommand = $Script:ScriptBlock
                    $Script:ObfuscatedCommandHistory = @($Script:ScriptBlock)
                    $Script:CliSyntax         = @()
                    $Script:ExecutionCommands = @()
                    
                    Write-Host "`n`nSuccessfully reset ObfuscatedCommand." -ForegroundColor Cyan
                }
            }
            ElseIf($UndoObfuscationInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCommand -ne $NULL) -AND ($Script:ObfuscatedCommand.Length -eq 0))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCommand has not been set. There is nothing to undo."
                }
                ElseIf($Script:ObfuscatedCommand -ceq $Script:ScriptBlock)
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCommand. There is nothing to undo."
                }
                Else
                {
                    # Set ObfuscatedCommand to the last state in ObfuscatedCommandHistory.
                    $Script:ObfuscatedCommand = $Script:ObfuscatedCommandHistory[$Script:ObfuscatedCommandHistory.Count-2]

                    # Remove the last state from ObfuscatedCommandHistory.
                    $Temp = $Script:ObfuscatedCommandHistory
                    $Script:ObfuscatedCommandHistory = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:ObfuscatedCommandHistory += $Temp[$i]
                    }

                    # Remove last command from CliSyntax. Trim all trailing OUT or CLIP commands until an obfuscation command is removed.
                    $CliSyntaxCount = $Script:CliSyntax.Count
                    While(($Script:CliSyntax[$CliSyntaxCount-1] -Match '^(clip|out )') -AND ($CliSyntaxCount -gt 0))
                    {
                        $CliSyntaxCount--
                    }
                    $Temp = $Script:CliSyntax
                    $Script:CliSyntax = @()
                    For($i=0; $i -lt $CliSyntaxCount-1; $i++)
                    {
                        $Script:CliSyntax += $Temp[$i]
                    }

                    # Remove last command from ExecutionCommands.
                    $Temp = $Script:ExecutionCommands
                    $Script:ExecutionCommands = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:ExecutionCommands += $Temp[$i]
                    }

                    # If this is removing a launcher then we must change the launcher state so we can continue obfuscating.
                    If($Script:LauncherApplied)
                    {
                        $Script:LauncherApplied = $FALSE
                        Write-Host "`n`nSuccessfully removed launcher from ObfuscatedCommand." -ForegroundColor Cyan
                    }
                    Else
                    {
                        Write-Host "`n`nSuccessfully removed last obfuscation from ObfuscatedCommand." -ForegroundColor Cyan
                    }
                }
            }
            ElseIf(($OutputToDiskInputOptions[0] -Contains $UserInput) -OR ($OutputToDiskInputOptions[0] -Contains $UserInput.Trim().Split(' ')[0]))
            {
                If(($Script:ObfuscatedCommand -ne '') -AND ($Script:ObfuscatedCommand -ceq $Script:ScriptBlock))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
                ElseIf($Script:ObfuscatedCommand -ne '')
                {
                    # Get file path information from compound user input (e.g. OUT C:\FILENAME.TXT).
                    If($UserInput.Trim().Split(' ').Count -gt 1)
                    {
                        # Get file path information from user input.
                        $UserInputOutputFilePath = $UserInput.Trim().SubString(4).Trim()
                        Write-Host ''
                    }
                    Else
                    {
                        # Get file path information from user interactively.
                        $UserInputOutputFilePath = Read-Host "`n`nEnter path for output file (or leave blank for default)"
                    }                    
                    # Decipher if user input a full file path, just a file name or nothing (default).
                    If($UserInputOutputFilePath.Trim() -eq '')
                    {
                        # User did not input anything so use default filename and current directory of this script.
                        $OutputFilePath = "$ScriptDir\Obfuscated_Command.txt"
                    }
                    ElseIf(!($UserInputOutputFilePath.Contains('\')) -AND !($UserInputOutputFilePath.Contains('/')))
                    {
                        # User input is not a file path so treat it as a filename and use current directory of this script.
                        $OutputFilePath = "$ScriptDir\$($UserInputOutputFilePath.Trim())"
                    }
                    Else
                    {
                        # User input is a full file path.
                        $OutputFilePath = $UserInputOutputFilePath
                    }
                    
                    # Write ObfuscatedCommand out to disk.
                    Write-Output $Script:ObfuscatedCommand > $OutputFilePath

                    If($Script:LauncherApplied -AND (Test-Path $OutputFilePath))
                    {
                        $Script:CliSyntax += "out $OutputFilePath"
                        Write-Host "`nSuccessfully output ObfuscatedCommand to" -NoNewLine -ForegroundColor Cyan
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                        Write-Host ".`nA Launcher has been applied so this script cannot be run as a standalone .ps1 file." -ForegroundColor Cyan
                        If($Env:windir) { C:\Windows\Notepad.exe $OutputFilePath }
                    }
                    ElseIf(!$Script:LauncherApplied -AND (Test-Path $OutputFilePath))
                    {
                        $Script:CliSyntax += "out $OutputFilePath"
                        Write-Host "`nSuccessfully output ObfuscatedCommand to" -NoNewLine -ForegroundColor Cyan
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                        Write-Host "." -ForegroundColor Cyan
                        If($Env:windir) { C:\Windows\Notepad.exe $OutputFilePath }
                    }
                    Else
                    {
                        Write-Host "`nERROR: Unable to write ObfuscatedCommand out to" -NoNewLine -ForegroundColor Red
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                    }
                }
                ElseIf($Script:ObfuscatedCommand -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " There isn't anything to write out to disk.`n       Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
            }
            ElseIf($CopyToClipboardInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCommand -ne '') -AND ($Script:ObfuscatedCommand -ceq $Script:ScriptBlock))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
                ElseIf($Script:ObfuscatedCommand -ne '')
                {
                    # Copy ObfuscatedCommand to clipboard.
                    # Try-Catch block introduced since PowerShell v2.0 without -STA defined will not be able to perform clipboard functionality.
                    Try
                    {
                        $Null = [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                        [Windows.Forms.Clipboard]::SetText($Script:ObfuscatedCommand)

                        If($Script:LauncherApplied)
                        {
                            Write-Host "`n`nSuccessfully copied ObfuscatedCommand to clipboard." -ForegroundColor Cyan
                        }
                        Else
                        {
                            Write-Host "`n`nSuccessfully copied ObfuscatedCommand to clipboard.`nNo Launcher has been applied, so command can only be pasted into powershell.exe." -ForegroundColor Cyan
                        }
                    }
                    Catch
                    {
                        $ErrorMessage = "Clipboard functionality will not work in PowerShell version $($PsVersionTable.PsVersion.Major) unless you add -STA (Single-Threaded Apartment) execution flag to powershell.exe."

                        If((Get-Command Write-Host).CommandType -ne 'Cmdlet')
                        {
                            # Retrieving Write-Host and Start-Sleep Cmdlets to get around the current proxy functions of Write-Host and Start-Sleep that are overloaded if -Quiet flag was used.
                            . ((Get-Command Write-Host)  | Where-Object {$_.CommandType -eq 'Cmdlet'}) "`n`nWARNING: " -NoNewLine -ForegroundColor Red
                            . ((Get-Command Write-Host)  | Where-Object {$_.CommandType -eq 'Cmdlet'}) $ErrorMessage -NoNewLine

                            . ((Get-Command Start-Sleep) | Where-Object {$_.CommandType -eq 'Cmdlet'}) 2
                        }
                        Else
                        {
                            Write-Host "`n`nWARNING: " -NoNewLine -ForegroundColor Red
                            Write-Host $ErrorMessage

                            If($Script:CliSyntax -gt 0) {Start-Sleep 2}
                        }
                    }
                    
                    $Script:CliSyntax += 'clip'
                }
                ElseIf($Script:ObfuscatedCommand -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " There isn't anything to copy to your clipboard.`n       Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand." -NoNewLine
                }
                
            }
            ElseIf($ExecutionInputOptions[0] -Contains $UserInput)
            {
                If($Script:LauncherApplied)
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " Cannot execute because you have applied a Launcher.`n       Enter" -NoNewLine
                    Write-Host " COPY" -NoNewLine -ForeGroundColor Yellow
                    Write-Host "/" -NoNewLine
                    Write-Host "CLIP" -NoNewLine -ForeGroundColor Yellow
                    Write-Host " and paste into cmd.exe.`n       Or enter" -NoNewLine
                    Write-Host " UNDO" -NoNewLine -ForeGroundColor Yellow
                    Write-Host " to remove the Launcher from ObfuscatedCommand."
                }
                ElseIf($Script:ObfuscatedCommand -ne '')
                {
                    If($Script:ObfuscatedCommand -ceq $Script:ScriptBlock) {Write-Host "`n`nInvoking (though you haven't obfuscated anything yet):"}
                    Else {Write-Host "`n`nInvoking:"}
                    
                    Out-ScriptContents $Script:ObfuscatedCommand
                    Write-Host ''
                    $null = Invoke-Expression $Script:ObfuscatedCommand
                }
                Else {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " Cannot execute because you have not set ScriptPath or ScriptBlock.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " to set ScriptPath or ScriptBlock."
                }
            }
            Else
            {
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host " You entered an invalid option. Enter" -NoNewLine
                Write-Host " HELP" -NoNewLine -ForegroundColor Yellow
                Write-Host " for more information."

                # If the failed input was part of $Script:CompoundCommand then cancel out the rest of the compound command so it is not further processed.
                If($Script:CompoundCommand.Count -gt 0)
                {
                    $Script:CompoundCommand = @()
                }

                # Output all available/acceptable options for current menu if invalid input was entered.
                If($AcceptableInput.Count -gt 1)
                {
                    $Message = 'Valid options for current menu include:'
                }
                Else
                {
                    $Message = 'Valid option for current menu includes:'
                }
                Write-Host "       $Message " -NoNewLine

                $Counter=0
                ForEach($AcceptableOption in $AcceptableInput)
                {
                    $Counter++

                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    If($SelectionContainsCommand)
                    {
                        $ColorToOutput = 'Green'
                    }
                    Else
                    {
                        $ColorToOutput = 'Yellow'
                    }

                    Write-Host $AcceptableOption -NoNewLine -ForegroundColor $ColorToOutput
                    If(($Counter -lt $AcceptableInput.Length) -AND ($AcceptableOption.Length -gt 0))
                    {
                        Write-Host ', ' -NoNewLine
                    }
                }
                Write-Host ''
            }
        }
    }
    
    Return $UserInput.ToLower()
}


Function Show-OptionsMenu
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays options menu for Invoke-Obfuscation.

Invoke-Obfuscation Function: Show-OptionsMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-OptionsMenu displays options menu for Invoke-Obfuscation.

.EXAMPLE

C:\PS> Show-OptionsMenu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Set potentially-updated script-level values in $Script:OptionsMenu before displaying.
    $Counter = 0
    ForEach($Line in $Script:OptionsMenu)
    {
        If($Line[0].ToLower().Trim() -eq 'scriptpath')            {$Script:OptionsMenu[$Counter][1] = $Script:ScriptPath}
        If($Line[0].ToLower().Trim() -eq 'scriptblock')           {$Script:OptionsMenu[$Counter][1] = $Script:ScriptBlock}
        If($Line[0].ToLower().Trim() -eq 'commandlinesyntax')     {$Script:OptionsMenu[$Counter][1] = $Script:CliSyntax}
        If($Line[0].ToLower().Trim() -eq 'executioncommands')     {$Script:OptionsMenu[$Counter][1] = $Script:ExecutionCommands}
        If($Line[0].ToLower().Trim() -eq 'obfuscatedcommand')
        {
            # Only add obfuscatedcommand if it is different than scriptblock (to avoid showing obfuscatedcommand before it has been obfuscated).
            If($Script:ObfuscatedCommand -cne $Script:ScriptBlock) {$Script:OptionsMenu[$Counter][1] = $Script:ObfuscatedCommand}
            Else {$Script:OptionsMenu[$Counter][1] = ''}
        }
        If($Line[0].ToLower().Trim() -eq 'obfuscationlength')
        {
            # Only set/display ObfuscationLength if there is an obfuscated command.
            If(($Script:ObfuscatedCommand.Length -gt 0) -AND ($Script:ObfuscatedCommand -cne $Script:ScriptBlock)) {$Script:OptionsMenu[$Counter][1] = $Script:ObfuscatedCommand.Length}
            Else {$Script:OptionsMenu[$Counter][1] = ''}
        }

        $Counter++
    }
    
    # Output menu.
    Write-Host "`n`nSHOW OPTIONS" -NoNewLine -ForegroundColor Cyan
    Write-Host " ::" -NoNewLine
    Write-Host " Yellow" -NoNewLine -ForegroundColor Yellow
    Write-Host " options can be set by entering" -NoNewLine
    Write-Host " SET OPTIONNAME VALUE" -NoNewLine -ForegroundColor Green
    Write-Host ".`n"
    ForEach($Option in $Script:OptionsMenu)
    {
        $OptionTitle = $Option[0]
        $OptionValue = $Option[1]
        $CanSetValue = $Option[2]
      
        Write-Host $LineSpacing -NoNewLine
        
        # For options that can be set by user, output as Yellow.
        If($CanSetValue) {Write-Host $OptionTitle -NoNewLine -ForegroundColor Yellow}
        Else {Write-Host $OptionTitle -NoNewLine}
        Write-Host ": " -NoNewLine
        
        # Handle coloring and multi-value output for ExecutionCommands and ObfuscationLength.
        If($OptionTitle -eq 'ObfuscationLength')
        {
            Write-Host $OptionValue -ForegroundColor Cyan
        }
        ElseIf($OptionTitle -eq 'ScriptBlock')
        {
            Out-ScriptContents $OptionValue
        }
        ElseIf($OptionTitle -eq 'CommandLineSyntax')
        {
            # CLISyntax output.
            $SetSyntax = ''
            If(($Script:ScriptPath.Length -gt 0) -AND ($Script:ScriptPath -ne 'N/A'))
            {
                $SetSyntax = " -ScriptPath '$Script:ScriptPath'"
            }
            ElseIf(($Script:ScriptBlock.Length -gt 0) -AND ($Script:ScriptPath -eq 'N/A'))
            {
                $SetSyntax = " -ScriptBlock {$Script:ScriptBlock}"
            }

            $CommandSyntax = ''
            If($OptionValue.Count -gt 0)
            {
                $CommandSyntax = " -Command '" + ($OptionValue -Join ',') + "' -Quiet"
            }

            If(($SetSyntax -ne '') -OR ($CommandSyntax -ne ''))
            {
                $CliSyntaxToOutput = "Invoke-Obfuscation" + $SetSyntax + $CommandSyntax
                Write-Host $CliSyntaxToOutput -ForegroundColor Cyan
            }
            Else
            {
                Write-Host ''
            }
        }
        ElseIf($OptionTitle -eq 'ExecutionCommands')
        {
            # ExecutionCommands output.
            If($OptionValue.Count -gt 0) {Write-Host ''}
            $Counter = 0
            ForEach($ExecutionCommand in $OptionValue)
            {
                $Counter++
                If($ExecutionCommand.Length -eq 0) {Write-Host ''; Continue}
            
                $ExecutionCommand = $ExecutionCommand.Replace('$ScriptBlock','~').Split('~')
                Write-Host "    $($ExecutionCommand[0])" -NoNewLine -ForegroundColor Cyan
                Write-Host '$ScriptBlock' -NoNewLine -ForegroundColor Magenta
                
                # Handle output formatting when SHOW OPTIONS is run.
                If(($OptionValue.Count -gt 0) -AND ($Counter -lt $OptionValue.Count))
                {
                    Write-Host $ExecutionCommand[1] -ForegroundColor Cyan
                }
                Else
                {
                    Write-Host $ExecutionCommand[1] -NoNewLine -ForegroundColor Cyan
                }

            }
            Write-Host ''
        }
        ElseIf($OptionTitle -eq 'ObfuscatedCommand')
        {
            Out-ScriptContents $OptionValue
        }
        Else
        {
            Write-Host $OptionValue -ForegroundColor Magenta
        }
    }
    
}


Function Show-HelpMenu
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays help menu for Invoke-Obfuscation.

Invoke-Obfuscation Function: Show-HelpMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-HelpMenu displays help menu for Invoke-Obfuscation.

.EXAMPLE

C:\PS> Show-HelpMenu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Show Help Menu.
    Write-Host "`n`nHELP MENU" -NoNewLine -ForegroundColor Cyan
    Write-Host " :: Available" -NoNewLine
    Write-Host " options" -NoNewLine -ForegroundColor Yellow
    Write-Host " shown below:`n"
    ForEach($InputOptionsList in $AllAvailableInputOptionsLists)
    {
        $InputOptionsCommands    = $InputOptionsList[0]
        $InputOptionsDescription = $InputOptionsList[1]

        # Add additional coloring to string encapsulated by <> if it exists in $InputOptionsDescription.
        If($InputOptionsDescription.Contains('<') -AND $InputOptionsDescription.Contains('>'))
        {
            $FirstPart  = $InputOptionsDescription.SubString(0,$InputOptionsDescription.IndexOf('<'))
            $MiddlePart = $InputOptionsDescription.SubString($FirstPart.Length+1)
            $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
            $LastPart   = $InputOptionsDescription.SubString($FirstPart.Length+$MiddlePart.Length+2)
            Write-Host "$LineSpacing $FirstPart" -NoNewLine
            Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
            Write-Host $LastPart -NoNewLine
        }
        Else
        {
            Write-Host "$LineSpacing $InputOptionsDescription" -NoNewLine
        }
        
        $Counter = 0
        ForEach($Command in $InputOptionsCommands)
        {
            $Counter++
            Write-Host $Command.ToUpper() -NoNewLine -ForegroundColor Yellow
            If($Counter -lt $InputOptionsCommands.Count) {Write-Host ',' -NoNewLine}
        }
        Write-Host ''
    }
}


Function Show-Tutorial
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays tutorial information for Invoke-Obfuscation.

Invoke-Obfuscation Function: Show-Tutorial
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-Tutorial displays tutorial information for Invoke-Obfuscation.

.EXAMPLE

C:\PS> Show-Tutorial

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Write-Host "`n`nTUTORIAL" -NoNewLine -ForegroundColor Cyan
    Write-Host " :: Here is a quick tutorial showing you how to get your obfuscation on:"
    
    Write-Host "`n1) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Load a scriptblock (SET SCRIPTBLOCK) or a script path/URL (SET SCRIPTPATH)."
    Write-Host "   SET SCRIPTBLOCK Write-Host 'This is my test command' -ForegroundColor Green" -ForegroundColor Green
    
    Write-Host "`n2) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Navigate through the obfuscation menus where the options are in" -NoNewLine
    Write-Host " YELLOW" -NoNewLine -ForegroundColor Yellow
    Write-Host "."
    Write-Host "   GREEN" -NoNewLine -ForegroundColor Green
    Write-Host " options apply obfuscation."
    Write-Host "   Enter" -NoNewLine
    Write-Host " BACK" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "CD .." -NoNewLine -ForegroundColor Yellow
    Write-Host " to go to previous menu and" -NoNewLine
    Write-Host " HOME" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "MAIN" -NoNewline -ForegroundColor Yellow
    Write-Host " to go to home menu.`n   E.g. Enter" -NoNewLine
    Write-Host " ENCODING" -NoNewLine -ForegroundColor Yellow
    Write-Host " & then" -NoNewLine
    Write-Host " 5" -NoNewLine -ForegroundColor Green
    Write-Host " to apply SecureString obfuscation."
    
    Write-Host "`n3) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " TEST" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "EXEC" -NoNewLine -ForegroundColor Yellow
    Write-Host " to test the obfuscated command locally.`n   Enter" -NoNewLine
    Write-Host " SHOW" -NoNewLine -ForegroundColor Yellow
    Write-Host " to see the currently obfuscated command."
    
    Write-Host "`n4) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " COPY" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "CLIP" -NoNewLine -ForegroundColor Yellow
    Write-Host " to copy obfuscated command out to your clipboard."
    Write-Host "   Enter" -NoNewLine
    Write-Host " OUT" -NoNewLine -ForegroundColor Yellow
    Write-Host " to write obfuscated command out to disk."
    
    Write-Host "`n5) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " RESET" -NoNewLine -ForegroundColor Yellow
    Write-Host " to remove all obfuscation and start over.`n   Enter" -NoNewLine
    Write-Host " UNDO" -NoNewLine -ForegroundColor Yellow
    Write-Host " to undo last obfuscation.`n   Enter" -NoNewLine
    Write-Host " HELP" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "?" -NoNewLine -ForegroundColor Yellow
    Write-Host " for help menu."
    
    Write-Host "`nAnd finally the obligatory `"Don't use this for evil, please`"" -NoNewLine -ForegroundColor Cyan
    Write-Host " :)" -ForegroundColor Green
}


Function Out-ScriptContents
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays current obfuscated command for Invoke-Obfuscation.

Invoke-Obfuscation Function: Out-ScriptContents
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-ScriptContents displays current obfuscated command for Invoke-Obfuscation.

.PARAMETER ScriptContents

Specifies the string containing your payload.

.PARAMETER PrintWarning

Switch to output redacted form of ScriptContents if they exceed 8,190 characters.

.EXAMPLE

C:\PS> Out-ScriptContents

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [Parameter(ValueFromPipeline = $true)]
        [String]
        $ScriptContents,

        [Switch]
        $PrintWarning
    )

    If($ScriptContents.Length -gt $CmdMaxLength)
    {
        # Output ScriptContents, handling if the size of ScriptContents exceeds $CmdMaxLength characters.
        $RedactedPrintLength = $CmdMaxLength/5
        
        # Handle printing redaction message in middle of screen. #OCD
        $CmdLineWidth = (Get-Host).UI.RawUI.BufferSize.Width
        $RedactionMessage = "<REDACTED: ObfuscatedLength = $($ScriptContents.Length)>"
        $CenteredRedactionMessageStartIndex = (($CmdLineWidth-$RedactionMessage.Length)/2) - "[*] ObfuscatedCommand: ".Length
        $CurrentRedactionMessageStartIndex = ($RedactedPrintLength % $CmdLineWidth)
        
        If($CurrentRedactionMessageStartIndex -gt $CenteredRedactionMessageStartIndex)
        {
            $RedactedPrintLength = $RedactedPrintLength-($CurrentRedactionMessageStartIndex-$CenteredRedactionMessageStartIndex)
        }
        Else
        {
            $RedactedPrintLength = $RedactedPrintLength+($CenteredRedactionMessageStartIndex-$CurrentRedactionMessageStartIndex)
        }
    
        Write-Host $ScriptContents.SubString(0,$RedactedPrintLength) -NoNewLine -ForegroundColor Magenta
        Write-Host $RedactionMessage -NoNewLine -ForegroundColor Yellow
        Write-Host $ScriptContents.SubString($ScriptContents.Length-$RedactedPrintLength) -ForegroundColor Magenta
    }
    Else
    {
        Write-Host $ScriptContents -ForegroundColor Magenta
    }

    # Make sure final command doesn't exceed cmd.exe's character limit.
    If($ScriptContents.Length -gt $CmdMaxLength)
    {
        If($PSBoundParameters['PrintWarning'])
        {
            Write-Host "`nWARNING: This command exceeds the cmd.exe maximum length of $CmdMaxLength." -ForegroundColor Red
            Write-Host "         Its length is" -NoNewLine -ForegroundColor Red
            Write-Host " $($ScriptContents.Length)" -NoNewLine -ForegroundColor Yellow
            Write-Host " characters." -ForegroundColor Red
        }
    }
}          


Function Show-AsciiArt
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays random ASCII art for Invoke-Obfuscation.

Invoke-Obfuscation Function: Show-AsciiArt
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-AsciiArt displays random ASCII art for Invoke-Obfuscation, and also displays ASCII art during script startup.

.EXAMPLE

C:\PS> Show-AsciiArt

.NOTES

Credit for ASCII art font generation: http://patorjk.com/software/taag/
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $Random
    )

    # Create multiple ASCII art title banners.
    $Spacing = "`t"
    $InvokeObfuscationAscii  = @()
    $InvokeObfuscationAscii += $Spacing + '    ____                 __                              '
    $InvokeObfuscationAscii += $Spacing + '   /  _/___ _   ______  / /_____                         '
    $InvokeObfuscationAscii += $Spacing + '   / // __ \ | / / __ \/ //_/ _ \______                  '
    $InvokeObfuscationAscii += $Spacing + ' _/ // / / / |/ / /_/ / ,< /  __/_____/                  '
    $InvokeObfuscationAscii += $Spacing + '/______ /__|_________/_/|_|\___/         __  _           '
    $InvokeObfuscationAscii += $Spacing + '  / __ \/ /_  / __/_  ________________ _/ /_(_)___  ____ '
    $InvokeObfuscationAscii += $Spacing + ' / / / / __ \/ /_/ / / / ___/ ___/ __ `/ __/ / __ \/ __ \'
    $InvokeObfuscationAscii += $Spacing + '/ /_/ / /_/ / __/ /_/ (__  ) /__/ /_/ / /_/ / /_/ / / / /'
    $InvokeObfuscationAscii += $Spacing + '\____/_.___/_/  \__,_/____/\___/\__,_/\__/_/\____/_/ /_/ '
    
    # Ascii art to run only during script startup.
    If(!$PSBoundParameters['Random'])
    {
        $ArrowAscii  = @()
        $ArrowAscii += '  |  '
        $ArrowAscii += '  |  '
        $ArrowAscii += ' \ / '
        $ArrowAscii += '  V  '

        # Show actual obfuscation example (generated with this tool) in reverse.
        Write-Host "`nIEX( ( '36{78Q55@32t61_91{99@104X97{114Q91-32t93}32t93}32t34@110m111@105}115X115-101m114_112@120@69-45{101@107X111m118m110-73Q124Q32X41Q57@51-93Q114_97_104t67t91{44V39Q112_81t109@39}101{99@97}108{112}101}82_45m32_32X52{51Q93m114@97-104{67t91t44t39V98t103V48t39-101}99}97V108}112t101_82_45{32@41X39{41_112t81_109_39m43{39-110t101@112{81t39X43@39t109_43t112_81Q109t101X39Q43m39}114Q71_112{81m109m39@43X39V32Q40}32m39_43_39{114-111m108t111t67{100m110{117Q39_43m39-111-114Q103_101t114@39m43-39{111t70-45}32m41}98{103V48V110Q98t103{48@39{43{39-43{32t98m103_48{111@105t98@103V48-39@43{39_32-32V43V32}32t98t103@48X116m97V99t98X103t48_39V43m39@43-39X43Q39_98@103@48}115V117V102Q98V79m45@98m39Q43{39X103_39X43Q39V48}43-39}43t39}98-103{48V101_107Q39t43X39_111X118X110V39X43}39t98_103{48@43}32_98{103}48{73{98-39@43t39m103_39}43{39{48Q32t39X43X39-32{40V32t41{39Q43V39m98X103{39_43V39{48-116{115Q79{39_43_39}98}103m48{39Q43t39X32X43{32_98@103-39@43m39X48_72-39_43t39V45m39t43Q39_101Q98}103_48-32_39Q43V39V32t39V43}39m43Q32V98X39Q43_39@103_48V39@43Q39@116X73t82V119m98-39{43_39}103Q48X40_46_32m39}40_40{34t59m91@65V114V114@97_121}93Q58Q58V82Q101Q118Q101{114}115_101m40_36_78m55@32t41t32-59{32}73{69V88m32{40t36V78t55}45Q74m111@105-110m32X39V39-32}41'.SpLiT( '{_Q-@t}mXV' ) |ForEach-Object { ([Int]`$_ -AS [Char]) } ) -Join'' )" -ForegroundColor Cyan
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}
        Start-Sleep -Milliseconds 100
        
        Write-Host "`$N7 =[char[ ] ] `"noisserpxE-ekovnI| )93]rahC[,'pQm'ecalpeR-  43]rahC[,'bg0'ecalpeR- )')pQm'+'nepQ'+'m+pQme'+'rGpQm'+' ( '+'roloCdnu'+'orger'+'oF- )bg0nbg0'+'+ bg0oibg0'+'  +  bg0tacbg0'+'+'+'bg0sufbO-b'+'g'+'0+'+'bg0ek'+'ovn'+'bg0+ bg0Ib'+'g'+'0 '+' ( )'+'bg'+'0tsO'+'bg0'+' + bg'+'0H'+'-'+'ebg0 '+' '+'+ b'+'g0'+'tIRwb'+'g0(. '((`";[Array]::Reverse(`$N7 ) ; IEX (`$N7-Join '' )" -ForegroundColor Magenta
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}
        Start-Sleep -Milliseconds 100

        Write-Host ".(`"wRIt`" +  `"e-H`" + `"Ost`") (  `"I`" +`"nvoke`"+`"-Obfus`"+`"cat`"  +  `"io`" +`"n`") -ForegroundColor ( 'Gre'+'en')" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline;  Write-Host $Line}
        Start-Sleep -Milliseconds 100

        Write-Host "Write-Host `"Invoke-Obfuscation`" -ForegroundColor Green" -ForegroundColor White
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line}
        Start-Sleep -Milliseconds 100
        
        # Write out below string in interactive format.
        Start-Sleep -Milliseconds 100
        ForEach($Char in [Char[]]'Invoke-Obfuscation')
        {
            Start-Sleep -Milliseconds (Get-Random -Input @(25..200))
            Write-Host $Char -NoNewline -ForegroundColor Green
        }
        
        Start-Sleep -Milliseconds 900
        Write-Host ""
        Start-Sleep -Milliseconds 300
        Write-Host

        # Display primary ASCII art title banner.
        $RandomColor = (Get-Random -Input @('Green','Cyan','Yellow'))
        ForEach($Line in $InvokeObfuscationAscii)
        {
            Write-Host $Line -ForegroundColor $RandomColor
        }
    }
    Else
    {
        # ASCII option in Invoke-Obfuscation interactive console.

    }

    # Output tool banner after all ASCII art.
    Write-Host ""
    Write-Host "`tTool    :: Invoke-Obfuscation" -ForegroundColor Magenta
    Write-Host "`tAuthor  :: Daniel Bohannon (DBO)" -ForegroundColor Magenta
    Write-Host "`tTwitter :: @danielhbohannon" -ForegroundColor Magenta
    Write-Host "`tBlog    :: http://danielbohannon.com" -ForegroundColor Magenta
    Write-Host "`tGithub  :: https://github.com/danielbohannon/Invoke-Obfuscation" -ForegroundColor Magenta
    Write-Host "`tVersion :: 1.8" -ForegroundColor Magenta
    Write-Host "`tLicense :: Apache License, Version 2.0" -ForegroundColor Magenta
    Write-Host "`tNotes   :: If(!`$Caffeinated) {Exit}" -ForegroundColor Magenta
}
