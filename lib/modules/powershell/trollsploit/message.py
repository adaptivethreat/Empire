from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Message',

            'Author': ['@harmj0y'],

            'Description': ("Displays a specified message to the user."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://blog.logrhythm.com/security/do-you-trust-your-computer/'
            ]
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
            'MsgText' : {
                'Description'   :   'Message text to display.',
                'Required'      :   True,
                'Value'         :   'Lost contact with the Domain Controller.'
            },
            'IconType' : {
                'Description'   :   'Critical, Question, Exclamation, or Information',
                'Required'      :   True,
                'Value'         :   'Critical'
            },
            'Title' : {
                'Description'   :   'Title of the message box to display.',
                'Required'      :   True,
                'Value'         :   'ERROR - 0xA801B720'
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
function Invoke-Message {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [String] $MsgText,
        
        [Parameter(Mandatory = $False, Position = 1)]
        [String] $IconType = 'Critical',

        [Parameter(Mandatory = $False, Position = 2)]
        [String] $Title = 'ERROR - 0xA801B720'
    )

    Add-Type -AssemblyName Microsoft.VisualBasic
    $null = [Microsoft.VisualBasic.Interaction]::MsgBox($MsgText, "OKOnly,MsgBoxSetForeground,SystemModal,$IconType", $Title)
}
Invoke-Message"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "computername":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " \"" + str(values['Value'].strip("\"")) + "\""
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
