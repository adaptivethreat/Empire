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



Function Out-EncodedSpecialCharOnlyCommand
{
<#
.SYNOPSIS

Generates Special-Character-Only encoded payload for a PowerShell command or script. Optionally it adds command line output to final command.
All credit for this encoding technique goes to 牟田口大介 (@mutaguchi) who blogged about it in 2010: http://perl-users.jp/articles/advent-calendar/2010/sym/11

Invoke-Obfuscation Function: Out-EncodedSpecialCharOnlyCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncodedSpecialCharOnlyCommand encodes an input PowerShell scriptblock or path as a Special-Character-Only payload. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

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

C:\PS> Out-EncodedSpecialCharOnlyCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive

powershell   -NoProf  -NonIn   "${      }=  +  $()  ;  ${  }=${      };${       }  =  ++  ${      };  ${    }=++${      }  ;${          }=++${      };${   }  =++  ${      }  ;  ${        }  =  ++${      };${            }  =++  ${      }  ;  ${           }=  ++${      }  ;${         }  =  ++  ${      }  ;  ${ }=++  ${      }  ;${     }=\"[\"+  \"$( @{ } ) \"[  ${           }]+\"$(@{  })\"[\"${       }${ }\"]+  \"$( @{ } ) \"[\"${    }${  }\"]+  \"$?\"[${       }  ]  +  \"]\"  ;${      }  =  \"\".(\"$( @{ } ) \"[\"${       }${   }\"  ]  +  \"$( @{ } ) \"[  \"${       }${            }\"]+  \"$( @{ } ) \"[${  }]  +\"$( @{ } ) \"[${   }  ]+  \"$?\"[${       }  ]  +\"$( @{ } ) \"[${          }]  )  ;  ${      }=  \"$( @{ } ) \"[  \"${       }${   }\"]+  \"$( @{ } ) \"[  ${   }]  +\"${      }\"[  \"${    }${           }\"]  ;  &  ${      }(  \"  ${     }${         }${           }  +${     }${       }${       }${   }  +  ${     }${       }${  }${        }+  ${     }${       }${       }${            }  +${     }${       }${  }${       }  +  ${     }${   }${        }+${     }${           }${    }+${     }${       }${       }${       }  +  ${     }${       }${       }${        }  +${     }${       }${       }${            }  +${     }${          }${    }  +${     }${          }${ }+  ${     }${           }${    }+  ${     }${       }${  }${       }+  ${     }${       }${  }${         }  +  ${     }${       }${  }${         }  +${     }${       }${       }${       }+  ${     }${          }${    }  +  ${     }${         }${           }+  ${     }${       }${       }${       }+  ${     }${       }${       }${   }  +  ${     }${       }${  }${         }+  ${     }${       }${  }${  }  +  ${     }${          }${          }+${     }${          }${ }+  ${     }${          }${    }  +${     }${   }${        }+${     }${           }${  }  +${     }${       }${       }${       }+  ${     }${       }${       }${   }+  ${     }${       }${  }${       }+${     }${       }${  }${          }+${     }${       }${       }${   }  +  ${     }${       }${       }${       }  +  ${     }${       }${       }${           }+${     }${       }${       }${  }+  ${     }${       }${  }${  }  +  ${     }${            }${           }  +${     }${       }${       }${       }+${     }${       }${  }${         }  +${     }${       }${       }${       }+${     }${       }${       }${   }  +${     }${          }${    }+${     }${           }${       }  +  ${     }${       }${       }${   }  +  ${     }${       }${  }${       }+  ${     }${       }${  }${       }+  ${     }${       }${       }${  }+${     }${        }${ }  +${     }${          }${    }  +  ${     }${         }${           }  +  ${     }${       }${       }${   }+  ${     }${       }${  }${        }+  ${     }${       }${       }${            }+${     }${       }${  }${       }  +${     }${   }${        }+${     }${           }${    }  +  ${     }${       }${       }${       }+${     }${       }${       }${        }  +${     }${       }${       }${            }+${     }${          }${    }  +${     }${          }${ }+  ${     }${           }${ }  +  ${     }${ }${         }  +  ${     }${       }${  }${    }+${     }${       }${       }${           }+${     }${       }${       }${        }+${     }${ }${ }  +${     }${ }${           }  +  ${     }${       }${       }${            }  +${     }${       }${  }${        }  +  ${     }${       }${       }${       }+  ${     }${       }${       }${  }  +${     }${          }${    }  +  ${     }${         }${    }+${     }${       }${       }${       }+${     }${ }${ }+${     }${       }${  }${           }+${     }${       }${       }${        }+  ${     }${          }${          }  +  ${     }${          }${ }  +${     }${          }${    }+  ${     }${   }${        }+${     }${           }${  }  +  ${     }${       }${       }${       }+${     }${       }${       }${   }  +${     }${       }${  }${       }  +  ${     }${       }${  }${          }  +  ${     }${       }${       }${   }+  ${     }${       }${       }${       }+  ${     }${       }${       }${           }+  ${     }${       }${       }${  }  +${     }${       }${  }${  }+  ${     }${            }${           }+${     }${       }${       }${       }  +  ${     }${       }${  }${         }+  ${     }${       }${       }${       }  +${     }${       }${       }${   }  +${     }${          }${    }+  ${     }${           }${       }+${     }${       }${       }${   }  +${     }${       }${  }${       }  +  ${     }${       }${  }${       }+${     }${       }${       }${  }^|${      }  \"  )"

C:\PS> Out-EncodedSpecialCharOnlyCommand -ScriptBlock {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} -NoProfile -NonInteractive -PassThru

${%``*}  =  +$()  ;  ${(\$}=${%``*}  ;  ${ *}=++  ${%``*};${$)(}  =  ++${%``*};${ }  =++${%``*};${,+]}=  ++  ${%``*}  ;  ${,}  =++  ${%``*};  ${!``@}  =++${%``*}  ;${.}  =  ++  ${%``*};  ${]\}=++  ${%``*}  ;${+}=++${%``*}  ;${,-\}="["+"$(@{})"[${.}]+  "$(@{})"["${ *}${+}"  ]+"$(@{})"["${$)(}${(\$}"  ]  +"$?"[  ${ *}]+  "]";${%``*}  =  "".("$(@{})"[  "${ *}${,+]}"  ]  +"$(@{})"["${ *}${!``@}"  ]+  "$(@{})"[${(\$}  ]  +  "$(@{})"[  ${,+]}]+  "$?"[  ${ *}]+"$(@{})"[${ }  ]  )  ;  ${%``*}  =  "$(@{})"["${ *}${,+]}"]+  "$(@{})"[${,+]}]+  "${%``*}"["${$)(}${.}"]  ;"  ${%``*}  (${,-\}${]\}${.}+${,-\}${ *}${ *}${,+]}  +  ${,-\}${ *}${(\$}${,}+  ${,-\}${ *}${ *}${!``@}+${,-\}${ *}${(\$}${ *}  +  ${,-\}${,+]}${,}+  ${,-\}${.}${$)(}  +  ${,-\}${ *}${ *}${ *}  +${,-\}${ *}${ *}${,}+${,-\}${ *}${ *}${!``@}+  ${,-\}${ }${$)(}+${,-\}${ }${+}  +${,-\}${.}${$)(}+${,-\}${ *}${(\$}${ *}+  ${,-\}${ *}${(\$}${]\}  +  ${,-\}${ *}${(\$}${]\}  +${,-\}${ *}${ *}${ *}+${,-\}${ }${$)(}+  ${,-\}${]\}${.}+${,-\}${ *}${ *}${ *}+${,-\}${ *}${ *}${,+]}  +${,-\}${ *}${(\$}${]\}  +  ${,-\}${ *}${(\$}${(\$}+  ${,-\}${ }${ }  +${,-\}${ }${+}  +  ${,-\}${ }${$)(}+  ${,-\}${,+]}${,}  +${,-\}${.}${(\$}  +  ${,-\}${ *}${ *}${ *}+${,-\}${ *}${ *}${,+]}+  ${,-\}${ *}${(\$}${ *}+${,-\}${ *}${(\$}${ }+${,-\}${ *}${ *}${,+]}+${,-\}${ *}${ *}${ *}  +${,-\}${ *}${ *}${.}+${,-\}${ *}${ *}${(\$}+  ${,-\}${ *}${(\$}${(\$}  +${,-\}${!``@}${.}  +${,-\}${ *}${ *}${ *}  +  ${,-\}${ *}${(\$}${]\}  +${,-\}${ *}${ *}${ *}+  ${,-\}${ *}${ *}${,+]}+${,-\}${ }${$)(}  +${,-\}${.}${ *}  +  ${,-\}${ *}${ *}${,+]}+  ${,-\}${ *}${(\$}${ *}  +  ${,-\}${ *}${(\$}${ *}+  ${,-\}${ *}${ *}${(\$}  +  ${,-\}${,}${+}+  ${,-\}${ }${$)(}  +${,-\}${]\}${.}  +  ${,-\}${ *}${ *}${,+]}+  ${,-\}${ *}${(\$}${,}+  ${,-\}${ *}${ *}${!``@}  +${,-\}${ *}${(\$}${ *}+${,-\}${,+]}${,}+${,-\}${.}${$)(}+${,-\}${ *}${ *}${ *}+${,-\}${ *}${ *}${,}+  ${,-\}${ *}${ *}${!``@}  +  ${,-\}${ }${$)(}  +${,-\}${ }${+}+  ${,-\}${.}${+}+  ${,-\}${+}${]\}  +${,-\}${ *}${(\$}${$)(}  +${,-\}${ *}${ *}${.}  +  ${,-\}${ *}${ *}${,}  +${,-\}${+}${+}+${,-\}${+}${.}  +${,-\}${ *}${ *}${!``@}+  ${,-\}${ *}${(\$}${,}  +${,-\}${ *}${ *}${ *}+  ${,-\}${ *}${ *}${(\$}+${,-\}${ }${$)(}+  ${,-\}${]\}${$)(}  +${,-\}${ *}${ *}${ *}  +${,-\}${+}${+}+${,-\}${ *}${(\$}${.}  +${,-\}${ *}${ *}${,}+  ${,-\}${ }${ }  +${,-\}${ }${+}+  ${,-\}${ }${$)(}  +  ${,-\}${,+]}${,}  +  ${,-\}${.}${(\$}+${,-\}${ *}${ *}${ *}+${,-\}${ *}${ *}${,+]}+${,-\}${ *}${(\$}${ *}  +${,-\}${ *}${(\$}${ }+${,-\}${ *}${ *}${,+]}  +  ${,-\}${ *}${ *}${ *}  +${,-\}${ *}${ *}${.}  +  ${,-\}${ *}${ *}${(\$}+${,-\}${ *}${(\$}${(\$}+${,-\}${!``@}${.}+  ${,-\}${ *}${ *}${ *}+${,-\}${ *}${(\$}${]\}  +  ${,-\}${ *}${ *}${ *}  +${,-\}${ *}${ *}${,+]}  +${,-\}${ }${$)(}+  ${,-\}${.}${ *}  +  ${,-\}${ *}${ *}${,+]}+${,-\}${ *}${(\$}${ *}  +${,-\}${ *}${(\$}${ *}+  ${,-\}${ *}${ *}${(\$}  )"|  .${%``*}

.NOTES

All credit for this encoding technique goes to 牟田口大介 (@mutaguchi) who blogged about it in 2010: http://perl-users.jp/articles/advent-calendar/2010/sym/11
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

    # Build out variables to obtain 0-9, "[char]" and "iex"
    $VariableInstantiationSyntax  = @()
    $VariableInstantiationSyntax += '${;} = + $( ) ; ${=} = ${;} ; ${+} = ++ ${;} ; ${@} = ++ ${;} ; ${.} = ++ ${;} ; ${[} = ++ ${;} ; ${]} = ++ ${;} ; ${(} = ++ ${;} ; ${)} = ++ ${;} ; ${&} = ++ ${;} ; ${|} = ++ ${;} ; '
    $VariableInstantiationSyntax += '${;} = + $( ) ; ${=} = ${;} ; ${+} = ++ ${;} ; ${@} = ( ${;} = ${;} + ${+} ) ; ${.} = ( ${;} = ${;} + ${+} ) ; ${[} = ( ${;} = ${;} + ${+} ) ; ${]} = ( ${;} = ${;} + ${+} ) ; ${(} = ( ${;} = ${;} + ${+} ) ; ${)} = ( ${;} = ${;} + ${+} ) ; ${&} = ( ${;} = ${;} + ${+} ) ; ${|} = ( ${;} = ${;} + ${+} ) ; '
    $VariableInstantiation = (Get-Random -Input $VariableInstantiationSyntax)

    ${[Char]}              = '${"} = \"[\" + \"$( @{ } ) \"[ ${)} ] + \"$(@{ })\"[ \"${+}${|}\" ] + \"$( @{ } ) \"[ \"${@}${=}\" ] + \"$? \"[ ${+} ] + \"]\" ; '
    $OverloadDefinitions   = '${;} = \"\".(\"$( @{ } ) \"[ \"${+}${[}\" ] + \"$( @{ } ) \"[ \"${+}${(}\" ] + \"$( @{ } ) \"[ ${=} ] + \"$( @{ } ) \"[ ${[} ] + \"$? \"[ ${+} ] + \"$( @{ } ) \"[ ${.} ] ) ; '
    $Iex                   = '${;} = \"$( @{ } ) \"[ \"${+}${[}\" ] + \"$( @{ } ) \"[ ${[} ] + \"${;}\"[ \"${@}${)}\" ] ; '

    # 1/2 of the time choose to change above variable string concatenation syntax from "${var1}${var2}" to "${var1}" + "${var2}".
    # This is so defenders won't place false hope in the presence of high counts of }${ for detecting this obfuscation syntax.
    If((Get-Random -Input @(0..1)))
    {
        ${[Char]} = ${[Char]}.Replace('}${','}\" + \"${')
    }

    # 1/2 of the time choose to change above variable string concatenation syntax from "${var1}${var2}" to "${var1}" + "${var2}".
    # This is so defenders won't place false hope in the presence of high counts of }${ for detecting this obfuscation syntax.
    If((Get-Random -Input @(0..1)))
    {
        $OverloadDefinitions = $OverloadDefinitions.Replace('}${','}\" + \"${')
    }

    # 1/2 of the time choose to change above variable string concatenation syntax from "${var1}${var2}" to "${var1}" + "${var2}".
    # This is so defenders won't place false hope in the presence of high counts of }${ for detecting this obfuscation syntax.
    If((Get-Random -Input @(0..1)))
    {
        $Iex = $Iex.Replace('}${','}\" + \"${')
    }

    # Combine above setup commands.
    $SetupCommand = $VariableInstantiation + ${[Char]} + $OverloadDefinitions + $Iex

    # 1/2 of the time choose 'char' | % syntax where only one ';' is needed in the entire command.
    # 1/2 of the time choose simpler ';' delimiter for each command.
    If((Get-Random -Input @(0..1)))
    {
        # Do not add ':' '?' '>' '<' '|' '&' ':' '^' "'" ',' or ' ' to this $NewCharacters list.
        $NewCharacters = @(';','=','+','@','.','[',']','(',')','-','_','/','\','*','%','$','#','!','``','~')

        # 1/3 of the time randomly choose using only one random character from above.
        # 2/3 of the time use eleven randomly chosen characters from $NewCharacters defined above.
        Switch(Get-Random -Input @(1..3))
        {
            1 {$RandomChar = (Get-Random -Input $NewCharacters); $RandomString = $RandomChar*(Get-Random -Input @(1..6))}
            default {$RandomString = (Get-Random -Input $NewCharacters -Count (Get-Random -Input @(1..3)))}
        }

        # Replace default syntax for multiple commands (using ';') with the syntax of 'char' | %
        $SetupCommand = '( ' + "'$RandomString'" + ' | % { ' + $SetupCommand.Replace(' ; ',' } { ').Trim(' {') + ' ) ; '
    }

    # Convert $ScriptString into a character array and then convert each character into ASCII integer representations substituted with our special character variables for each character.
    $CharEncoded = ([Char[]]$ScriptString | ForEach-Object {'${"}'+ ([Int]$_  -Replace "0",'${=}' -Replace "1",'${+}' -Replace "2",'${@}' -Replace "3",'${.}' -Replace "4",'${[}' -Replace "5",'${]}' -Replace "6",'${(}' -Replace "7",'${)}' -Replace "8",'${&}' -Replace "9",'${|}')}) -Join ' + '
    
    # Randomly choose between . and & invocation operators.
    $InvocationSyntax = (Get-Random -Input @('.','&'))

    # Select random ordering for both layers of "iex"
    $CharEncodedSyntax  = @()
    $CharEncodedSyntax += '\" ' + $CharEncoded + ' ^| ${;} \" | ' + $InvocationSyntax + ' ${;} '
    $CharEncodedSyntax += '\" ${;} ( ' + $CharEncoded + ' ) \" | ' + $InvocationSyntax + ' ${;} '
    $CharEncodedSyntax += $InvocationSyntax + ' ${;} ( \" ' + $CharEncoded + ' ^| ${;} \" ) '
    $CharEncodedSyntax += $InvocationSyntax + ' ${;} ( \" ${;} ( ' + $CharEncoded + ' ) \" ) '

    # Randomly select one of the above commands.
    $CharEncodedRandom  = (Get-Random -Input $CharEncodedSyntax)
    
    # Combine variable instantion $SetupCommand and our encoded command.
    $NewScriptTemp = $SetupCommand + $CharEncodedRandom

    # Insert random whitespace.
    $NewScript = ''
    $NewScriptTemp.Split(' ') | ForEach-Object {
        $NewScript += $_ + ' '*(Get-Random -Input @(0,2))
    }

    # Substitute existing character placement with randomized variables names consisting of randomly selected special characters.    
    $DefaultCharacters = @(';','=','+','@','.','[',']','(',')','&','|','"')

    # Do not add ':' '?' '>' '<' '|' '&' ':' '_' ',' or '^' to this $NewCharacters list.
    $NewCharacters     = @(';','=','+','@','.','[',']','(',')','-','/',"'",'*','%','$','#','!','``','~',' ')

    # 1/3 of the time randomly choose using only one random character from above or using only whitespace for variable names.
    # 2/3 of the time use eleven randomly chosen characters from $NewCharacters defined above.
    $UpperLimit = 1
    Switch(Get-Random -Input @(1..6))
    {
        1 {$RandomChar = (Get-Random -Input $NewCharacters); $NewCharacters = @(1..12) | ForEach-Object {$RandomChar*$_}}
        2 {$NewCharacters = @(1..12) | ForEach-Object {' '*$_}}
        default {$UpperLimit = 3}
    }

    $NewVariableList  = @()
    While($NewVariableList.Count -lt $DefaultCharacters.Count)
    {
        $CurrentVariable = (Get-Random -Input $NewCharacters -Count (Get-Random -Input @(1..$UpperLimit))) -Join ''
        While($NewVariableList -Contains $CurrentVariable)
        {
            $CurrentVariable = (Get-Random -Input $NewCharacters -Count (Get-Random -Input @(1..$UpperLimit))) -Join ''
        }
        $NewVariableList += $CurrentVariable
    }

    # Select 10 random new variable names and substitute the existing special characters in $NewScript.
    $NewCharactersRandomOrder = Get-Random -Input $NewCharacters -Count $DefaultCharacters.Count

    For($i=0; $i -lt $DefaultCharacters.Count; $i++)
    {
        $NewScript = $NewScript.Replace(('${' + $DefaultCharacters[$i] + '}'),('${' + $i + '}'))
    }
    For($i=$DefaultCharacters.Count-1; $i -ge 0; $i--)
    {
        $NewScript = $NewScript.Replace(('${' + $i + '}'),('${' + $NewVariableList[$i]+'}'))
    }

    # Remove certain escaping if PassThru is selected.
    If($PSBoundParameters['PassThru'])
    {
        If($NewScript.Contains('\"'))
        {
            $NewScript = $NewScript.Replace('\"','"')
        }
        If($NewScript.Contains('^|'))
        {
            $NewScript = $NewScript.Replace('^|','|')
        }
    }

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