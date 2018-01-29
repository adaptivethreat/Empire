from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SQLQuery',
            'Author': ['@_nullbind', '@0xbadjuju'],
            'Description': ('Executes a query on target SQL servers.'),
            'Background' : True,
            'OutputExtension' : None,
            
            'NeedsAdmin' : False,
            'OpsecSafe' : True,
            'Language' : 'powershell',
			'MinPSVersion' : '2',
            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1'
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
                'Description'   :   'SQL Server or domain account to authenticate with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'SQL Server or domain account password to authenticate with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Instance' : {
                'Description'   :   'SQL Server instance to connection to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Query' : {
                'Description'   :   'Query to be executed on the SQL Server.',
                'Required'      :   True,
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
        query = self.options['Query']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "data/module_source/collection/Get-SQLQuery.ps1"
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

        scriptEnd = " Get-SQLQuery"
        if username != "":
            scriptEnd += " -Username "+username
        if password != "":
            scriptEnd += " -Password "+password
        if instance != "":
            scriptEnd += " -Instance "+instance
        scriptEnd += " -Query "+"\'"+query+"\'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
