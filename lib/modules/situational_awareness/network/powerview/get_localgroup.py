from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-NetLocalGroup',

            'Author': ['@harmj0y'],

            'Description': ('Returns a list of all current users in a specified local group '
                            'on a local or remote machine. Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [ ]
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
                'Description'   :   'The hostname or IP to query for local group users.',
                'Required'      :   False,
                'Value'         :   'localhost'
            },
            'GroupName' : {
                'Description'   :   'The local group name to query for users, defaults to "Administrators".',
                'Required'      :   False,
                'Value'         :   'Administrators'
            },
            'ListGroups' : {
                'Description'   :   'Switch. List all the local groups instead of their members.',
                'Required'      :   False,
                'Value'         :   ''
            },            
            'Recurse' : {
                'Description'   :   'Switch. If the local member member is a domain group, recursively try to resolve its members to get a list of domain users who can access this machine.',
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
