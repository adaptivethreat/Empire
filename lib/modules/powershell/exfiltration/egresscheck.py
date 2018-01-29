from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Invoke-EgressCheck',

            # list of one or more authors for the module
            'Author': ['Stuart Morgan <stuart.morgan@mwrinfosecurity.com>'],

            # more verbose multi-line description of the module
            'Description': ('This module will generate traffic on a provided range of ports '
                            'and supports both TCP and UDP. Useful to identify direct egress channels.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            # Disabled - this can be a relatively noisy module but sometimes useful
            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            # list of any references/other comments
            'Comments': [
                'https://github.com/stufus/egresscheck-framework'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to generate the source traffic on',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ip' : {
                'Description'   :   'Target IP Address',
                'Required'      :   True,
                'Value'         :   ''
            },
            'protocol' : {
                'Description'   :   'The protocol to use. This can be TCP or UDP',
                'Required'      :   True,
                'Value'         :   'TCP'
            },
            'portrange' : {
                'Description'   :   'The range of ports to connect on. This can be a comma separated list or dash-separated ranges.',
                'Required'      :   True,
                'Value'         :   '22-25,53,80,443,445,3306,3389'
            },
            'delay' : {
                'Description'   :   'Delay, in milliseconds, between ports being tested',
                'Required'      :   True,
                'Value'         :   '50'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        # if you're reading in a large, external script that might be updates,
        #   use the pattern below
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/exfil/Invoke-EgressCheck.ps1"
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

        # Need to actually run the module that has been loaded
        scriptEnd = 'Invoke-EgressCheck'

        # add any arguments to the end execution of the script
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " \"" + str(values['Value']) + "\""
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
