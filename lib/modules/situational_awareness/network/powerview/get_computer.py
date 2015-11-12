from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-NetComputer',

            'Author': ['@harmj0y'],

            'Description': ('Queries the domain for current computer objects. Part of PowerView.'),

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
            'ComputerName' : {
                'Description'   :   'Return computers with a specific name, wildcards accepted.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SPN' : {
                'Description'   :   'Return computers with a specific service principal name, wildcards accepted.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'OperatingSystem' : {
                'Description'   :   'Return computers with a specific operating system, wildcards accepted.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Filter' : {
                'Description'   :   'A customized ldap filter string to use, e.g. "(description=*admin*)"',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Printers' : {
                'Description'   :   'Switch. Return only printers.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Ping' : {
                'Description'   :   "Switch. Ping each host to ensure it's up before enumerating.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'FullData' : {
                'Description'   :   "Switch. Return full computer objects instead of just system names (the default).",
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
