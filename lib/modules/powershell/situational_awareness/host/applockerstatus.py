from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-AppLockerConfig',
            'Author': ['@matterpreter', 'Matt Hand'],
            'Description': ('This script is used to query the current AppLocker '
                            'policy on the target and check the status of a user-defined '
                            'executable or all executables in a path.'),
            'Background': False,
            'OutputExtension': None,
            'NeedsAdmin': False,
            'OpsecSafe': True,
            'Language': 'powershell',
            'MinLanguageVersion': '2',
            'Comments': [
                'comment',
                'https://github.com/matterpreter/misc/blob/master/Get-AppLockerConfig.ps1'
            ]
        }

        self.options = {
            'Agent': {
                'Description':   'Agent to run module on.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Executable': {
                'Description':   'Full filepath of executable or folder to check.',
                'Required'   :   True,
                'Value'      :   'c:\windows\system32\*.exe'
            },
            'User': {
                'Description':   'Username to test the execution policy for.',
                'Required'   :   False,
                'Value'      :   'Everyone'
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters are passed as
        #   an object set to the module and the options dictionary is
        #   automatically set. This is mostly in case options are passed on
        #   the command line.
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        script = """
function Get-AppLockerConfig
{
    <#
    .SYNOPSIS

    This script is used to query the current AppLocker policy for a specified executable.

    Author: Matt Hand (@matterpreter)
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.0

    .DESCRIPTION

    This script is used to query the current AppLocker policy on the target and check the status of a user-defined executable or all executables in a path.

    .PARAMETER Executable

    Full filepath of the executable to test. This also supports wildcards (*) to test all executables in a directory.

    .PARAMETER User

    User to test the policy for. Default is "Everyone."

    .EXAMPLE

    Get-AppLockerStatus 'c:\windows\system32\calc.exe'
    Tests the AppLocker policy for calc.exe for "Everyone."

    Get-AppLockerStatus 'c:\users\jdoe\Desktop\*.exe' 'dguy'
    Tests the AppLocker policy for "dguy" against every file ending in ".exe" in jdoe's Desktop folder.

    #>
    Param(
          [Parameter(Mandatory=$true)]
          [string]$Executable,
          [string]$User = 'Everyone'
    )

    if (-NOT (test-path $Executable)){
        Write-Output "[-] Executable not found or you do not have access to it. Exiting..."
        Return
        }

    if (-NOT (Get-WmiObject Win32_UserAccount -Filter "LocalAccount='true' and Name='$User'")){
        Write-Output "[-] User does not exist. Exiting..."
        Return
        }


    $AppLockerCheck = Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path $Executable -User $User
    $AppLockerStatus = $AppLockerCheck | Select-String -InputObject {$_.PolicyDecision} -Pattern "Allowed"

    if ($AppLockerStatus -Match 'Allowed') { $Result = "[+] $Executable - ALLOWED for $User!" }
    else { $Result = "[-] $Executable - BLOCKED for $USER"}

    $Result
} Get-AppLockerConfig"""

        scriptEnd = ""

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
