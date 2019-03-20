from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-SMBLogin',

            'Author': ['Mauricio Velazco (@mvelazco)'],

            # More verbose multi-line description of the module
            'Description': ('Validates username & password combination(s) across a host or group of hosts using the SMB protocol.'),

            'Background': False,

            'OutputExtension': None,

            'NeedsAdmin': False,

            'OpsecSafe': True,

            'Language': 'powershell',

            'MinLanguageVersion': '2',

            'Comments': ['Github:','https://github.com/mvelazc0/Invoke-SMBLogin']
        }

        self.options = {
            'Agent': {

                'Description':   'Agent to grab a screenshot from.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ComputerName': {
                'Description': 'A single computer name (ip) or a list of comma separated computer names (ips)',
                'Required': True,
                'Value': ''
            },
            'Domain': {
                'Description': 'Domain to use. If not defined, local accounts will be used',
                'Required': False,
                'Value': ''
            },
            'Password': {
                'Description': 'A single password or list of comma separated passwords',
                'Required': True,
                'Value': ''
            },
            'UserName': {
                'Description': 'A single username or a list of comma separated usernames',
                'Required': True,
                'Value': ''
            }
        }

        self.mainMenu = mainMenu

        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-SMBLogin.ps1"
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
        scriptEnd = ""

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":

            if not self.mainMenu.credentials.is_credential_valid(credID):
                print
                helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = \
            self.mainMenu.credentials.get_credentials(credID)[0]

            if domainName != "":
                self.options["Domain"]['Value'] = str(domainName)
                self.options["UserName"]['Value'] = str(userName)
            else:
                self.options["UserName"]['Value'] = str(userName)
                self.options["Domain"]['Value'] = ""
            if password != "":
                self.options["Password"]['Value'] = password

        if self.options["UserName"]['Value'] == "" or self.options["Password"]['Value'] == "":
            print
            helpers.color("[!] Username and password must be specified.")

        scriptEnd += "Invoke-SMBLogin "

        for option, values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "credid":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)

        scriptEnd += "| Out-String | %{$_ + \"`n\"};"
        scriptEnd += "'Invoke-SMBLogin completed'"

        script += scriptEnd
        print script
        return script