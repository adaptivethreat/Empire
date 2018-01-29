import base64
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'HTTP-Login',

            'Author': ['@424f424f'],

            'Description': ("Tests credentials against Basic Authentication."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,
 
            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://www.rvrsh3ll.net'
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
            'Rhosts' : {
                'Description'   :   'Specify the CIDR range or host to scan.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Port' : {
                'Description'   :   'Specify the port to scan.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Directory' : {
                'Description'   :   'Specify the path to authentication (e.g. /manager/html)',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Username' : {
                'Description'   :   'Set the username to test.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Set the password to test.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Dictionary' : {
                'Description'   :   'Set the password dictionary file.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UseSSL' : {
                'Description'   :   'Force SSL useage.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Threads' : {
                'Description'   :   'The maximum concurrent threads to execute.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'NoPing' : {
                'Description'   :   'Switch. Disable ping check.',
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
        
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/recon/HTTP-Login.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        scriptEnd = "\nTest-Login"

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "showall":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value']) 

        scriptEnd += " | Out-String"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
