from lib.common import helpers
import os

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-UserHunter',

            'Author': ['@harmj0y'],

            'Description': ('Finds which machines users of a specified group are logged into. '
                            'Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/Veil-Framework/PowerTools/tree/master/PowerView'
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
            'Hosts' : {
                'Description'   :   'Hosts to enumerate.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HostList' : {
                'Description'   :   'Hostlist to enumerate.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'HostFilter' : {
                'Description'   :   'Host filter name to query AD for, wildcards accepted.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                'Description'   :   'Specific username to search for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'GroupName' : {
                'Description'   :   'Group to query for user names.',
                'Required'      :   False,
                'Value'         :   ''            
            },
            'UserList' : {
                'Description'   :   'List of usernames to search for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'StopOnSuccess' : {
                'Description'   :   'Switch. Stop when a target user is found.',
                'Required'      :   False,
                'Value'         :   ''
            },      
            'NoPing' : {
                'Description'   :   'Don\'t ping each host to ensure it\'s up before enumerating.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckAccess' : {
                'Description'   :   'Switch. Check if the current user has local admin access to found machines.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Delay' : {
                'Description'   :   'Delay between enumerating hosts, defaults to 0.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ShowAll' : {
                'Description'   :   'Switch. Show all result output.',
                'Required'      :   False,
                'Value'         :   ''            
            },
            'Domain' : {
                'Description'   :   'Domain to enumerate for hosts.',
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
        
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-UserHunter.ps1".replace('/', os.sep)

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        script += "Invoke-UserHunter "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 
        
        script += "| Select-Object TargetUser, Computer, IP, SessionFrom, LocalAdmin | ft -autosize | Out-String | %{$_ + \"`n\"}"

        script += ';"`nInvoke-UserHunter completed"'

        return script
