from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-ObjectAcl',

            'Author': ['@harmj0y', '@pyrotek3'],

            'Description': ('Returns the ACLs associated with a specific active directory object. Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView'
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
            'SamAccountName' : {
                'Description'   :   'Object SamAccountName to filter for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Name' : {
                'Description'   :   'Object Name to filter for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DistinguishedName' : {
                'Description'   :   'Object distinguished name to filter for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ResolveGUIDs' : {
                'Description'   :   'Switch. Resolve GUIDs to their display names.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'Filter' : {
                'Description'   :   'A customized ldap filter string to use, e.g. "(description=*admin*)"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ADSpath' : {
                'Description'   :   'The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ADSprefix' : {
                'Description'   :   'Prefix to set for the searcher (like "CN=Sites,CN=Configuration")',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RightsFilter' : {
                'Description'   :   'Only return results with the associated rights, "All", "ResetPassword","ChangePassword","WriteMembers"',
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


    def generate(self):
        
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

        return script