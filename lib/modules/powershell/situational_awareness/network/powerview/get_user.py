from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-NetUser',

            'Author': ['@harmj0y'],

            'Description': ('Query information for a given user or users in the specified domain. Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/'
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
            'UserName' : {
                'Description'   :   'Username filter string, wildcards accepted.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'The domain to use for the query, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainController' : {
                'Description'   :   'Domain controller to reflect LDAP queries through.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ADSpath' : {
                'Description'   :   'The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AdminCount' : {
                'Description'   :   'Switch. Return users with adminCount=1 (i.e. privileged users).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Filter' : {
                'Description'   :   'A customized ldap filter string to use, e.g. "(description=*admin*)"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SPN' : {
                'Description'   :   'Switch. Only return user objects with non-null service principal names.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AllowDelegation' : {
                'Description'   :   "Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'.",
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
        
        moduleName = self.info["Name"]
        
        # read in the common powerview.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/powerview.ps1"

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        # get just the code needed for the specified function
        script = helpers.generate_dynamic_powershell_script(moduleCode, moduleName)

        script += moduleName + " "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 

        script += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
        if obfuscate:
            script = helpers.obfuscate(psScript=script, obfuscationCommand=obfuscationCommand)
        return script
