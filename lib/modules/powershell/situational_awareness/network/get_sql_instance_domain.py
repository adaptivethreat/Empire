from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name' : 'Get-SQLInstanceDomain',
            'Author': ['@_nullbind', '@0xbadjuju'],
            'Description': ('Returns a list of SQL Server instances discovered by querying '
                            'a domain controller for systems with registered MSSQL service '
                            'principal names. The function will default to the current user\'s ' 
                            'domain and logon server, but an alternative domain controller '
                            'can be provided. UDP scanning of management servers is optional.'),
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
            'DomainController' : {
                'Description'   :   "Domain controller for Domain and Site that you want to query against.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'ComputerName' : {
                'Description'   :   'Computer name to filter for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainServiceAccount' : {
                'Description'   :   'Domain account to filter for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckMgmt' : {
                'Description'   :   'Performs UDP scan of servers managing SQL Server clusters.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'UDPTimeOut' : {
                'Description'   :   'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.',
                'Required'      :   False,
                'Value'         :   '3'
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
            }
        }

        self.mainMenu = mainMenu
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        domainController = self.options['DomainController']['Value']
        computerName = self.options['ComputerName']['Value']
        domainAccount = self.options['DomainServiceAccount']['Value']
        checkMgmt = self.options['CheckMgmt']['Value']
        udpTimeOut = self.options['UDPTimeOut']['Value']
        username = self.options['Username']['Value']
        password = self.options['Password']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Get-SQLInstanceDomain.ps1"
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

        scriptEnd = " Get-SQLInstanceDomain"
        if username != "":
            scriptEnd += " -Username " + username
        if password != "":
            scriptEnd += " -Password " + password
        if domainController != "":
            scriptEnd += " -DomainController "+domainController
        if computerName != "":
            scriptEnd += " -ComputerName "+computerName
        if domainAccount != "":
            scriptEnd += " -DomainAccount "+domainAccount
        if checkMgmt.lower() != "false":
	    scriptEnd += " -CheckMgmt"
            if udpTimeOut != "":
                scriptEnd += " -UDPTimeOut "+udpTimeOut
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
