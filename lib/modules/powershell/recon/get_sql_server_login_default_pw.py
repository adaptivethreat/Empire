from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SQLServerLoginDefaultPw',
            'Author': ['@_nullbind', '@0xbadjuju'],
            'Description': ('Based on the instance name, test if SQL Server '
                            'is configured with default passwords.'),
            'Background' : True,
            'OutputExtension' : None,
            
            'NeedsAdmin' : False,
            'OpsecSafe' : True,
            'Language' : 'powershell',
            'MinPSVersion' : '2',    
            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1',
                'https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md'
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
            'Username' : {
                'Description'   :   'SQL Server or domain account to authenticate with. Only used for CheckAll',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'SQL Server or domain account password to authenticate with. Only used for CheckAll',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Instance' : {
                'Description'   :   'SQL Server instance to connection to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckAll' : {
                'Description'   :   'Check all systems retrieved by Get-SQLInstanceDomain.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        self.mainMenu = mainMenu
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):
        username = self.options['Username']['Value']
        password = self.options['Password']['Value']
        instance = self.options['Instance']['Value']
        check_all = self.options['CheckAll']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "data/module_source/recon/Get-SQLServerLoginDefaultPw.ps1"
        script = ""
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            with open(moduleSource, 'r') as source:
                script = source.read()
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        if check_all:
            auxModuleSource = self.mainMenu.installPath + "data/module_source/situational_awareness/network/Get-SQLInstanceDomain.ps1"
            if obfuscate:
                helpers.obfuscate_module(moduleSource=auxModuleSource, obfuscationCommand=obfuscationCommand)
                auxModuleSource = moduleSource.replace("module_source", "obfuscated_module_source")
            try:
                with open(auxModuleSource, 'r') as auxSource:
                    auxScript = auxSource.read()
                    script += " " + auxScript
            except:
                print helpers.color("[!] Could not read additional module source path at: " + str(auxModuleSource))
            scriptEnd = " Get-SQLInstanceDomain "
            if username != "":
                scriptEnd += " -Username "+username
            if password != "":
                scriptEnd += " -Password "+password
            scriptEnd += " | Select Instance | "
        scriptEnd += " Get-SQLServerLoginDefaultPw"
        if instance != "" and not check_all:
            scriptEnd += " -Instance "+instance
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script