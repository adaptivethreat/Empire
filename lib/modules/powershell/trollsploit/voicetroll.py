import base64
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-VoiceTroll',

            'Author': ['@424f424f'],

            'Description': ("Reads text aloud via synthesized voice on target."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://www.instructables.com/id/Make-your-computer-talk-with-powershell/'
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
            'VoiceText' : {
                'Description'   :   'Text to synthesize on target.',
                'Required'      :   True,
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
Function Invoke-VoiceTroll

{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $VoiceText
    )

    Set-StrictMode -version 2
    Add-Type -AssemblyName System.Speech
    $synth = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
    $synth.Speak($VoiceText)
}
Invoke-VoiceTroll"""

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
