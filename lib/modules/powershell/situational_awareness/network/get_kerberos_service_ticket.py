from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Get-KerberosServiceTicket',

            # List of one or more authors for the module
            'Author': ['@OneLogicalMyth'],

            # More verbose multi-line description of the module
            'Description': ('Retrieves IP addresses and usernames using event ID 4769 this can allow identification of a users machine. Can only run on a domain controller.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # The language for this module
            'Language': 'powershell',

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion': '2',

            # List of any references/other comments
            'Comments': [
                'https://github.com/OneLogicalMyth/Empire'
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # Format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description':   'Agent to use for the event log search',
                'Required'   :   True,
                'Value'      :   ''
            },
            'UserName': {
                'Description':   'UserName to find, must be in the format of username@domain.local',
                'Required'   :   False,
                'Value'      :   ''
            },
            'MaxEvents': {
                'Description':   'Maximum events to return',
                'Required'   :   False,
                'Value'      :   '1000'
            },
            'ExcludeComputers': {
                'Description':   'Exclude computers from the results',
                'Required'   :   False,
                'Value'      :   'True'
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

        username = self.options['UserName']['Value']
        maxevents = self.options['MaxEvents']['Value']
        excludecomputers = self.options['ExcludeComputers']['Value']
        
        # Read in the source script
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Get-KerberosServiceTicket.ps1"
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

        scriptEnd = "Get-KerberosServiceTicket"
        if username != "":
            scriptEnd += " -UserName " + username
        if maxevents != "":
            scriptEnd += " -MaxEvents " + maxevents
        if excludecomputers == 'True':
        	scriptEnd += " -ExcludeComputers $true"
        if excludecomputers == 'False':
        	scriptEnd += " -ExcludeComputers $false"

        scriptEnd += " | Format-Table -AutoSize | Out-String"

        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script