from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            'Name': 'Invoke-Paranoia',
            
            'Author': ['pasv'],
            
            'Description': ('Continuously check running processes for the presence of suspicious users, members of groups, process names, and for any processes running off of USB drives.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : True,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                 'http://shell.fishing/code/Invoke-Paranoia.ps1'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to deploy Paranoia on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'WatchProcesses' : {
                'Description'   :   'Process names to watch out for. Default list is already appended.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WatchUsers' : {
                'Description'   :   'Users to watch out for in the form of domain\user, domain\user2, localuser',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WatchGroups' : {
                'Description'   :   'AD Groups to watch out for (Default is \'Domain Admins\')',
                'Required'      :   False,
                'Value'         :   ''
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/host/Invoke-Paranoia.ps1"
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

        scriptEnd = "Invoke-Paranoia "

        # add any arguments to the end execution of the script
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
