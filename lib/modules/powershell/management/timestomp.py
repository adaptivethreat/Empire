from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Timestomp',

            'Author': ['@obscuresec'],

            'Description': ('Executes time-stomp like functionality by '
                            'invoking Set-MacAttribute.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://obscuresecurity.blogspot.com/2014/05/touch.html'
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
            'FilePath' : {
                'Description'   :   'File path to modify.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'OldFile' : {
                'Description'   :   'Old file path to clone MAC from.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Modified' : {
                'Description'   :   'Set modified time (01/03/2006 12:12 pm).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Accessed' : {
                'Description'   :   'Set accessed time (01/03/2006 12:12 pm).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Created' : {
                'Description'   :   'Set created time (01/03/2006 12:12 pm).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'All' : {
                'Description'   :   'Set all MAC attributes to value (01/03/2006 12:12 pm).',
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Set-MacAttribute.ps1"
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

        scriptEnd = "\nSet-MacAttribute"

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    scriptEnd += " -" + str(option) + " \"" + str(values['Value']) + "\""

        scriptEnd += "| Out-String"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
