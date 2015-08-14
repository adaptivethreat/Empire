from lib.common import helpers
import os

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Netview',

            'Author': ['@harmj0y'],

            'Description': ('Queries the domain for all hosts, and retrieves open shares, '
                            'sessions, and logged on users for each host. Part of PowerView.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'MinPSVersion' : '2',
            
            'Comments': [
                'https://github.com/Veil-Framework/PowerTools/tree/master/PowerView',
                'https://github.com/mubix/netview'
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
            'NoPing' : {
                'Description'   :   'Don\'t ping each host to ensure it\'s up before enumerating.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckShareAccess' : {
                'Description'   :   'Switch. Only display found shares that the local user has access to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Delay' : {
                'Description'   :   'Delay between enumerating hosts, defaults to 0.',
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/network/Invoke-Netview.ps1".replace('/', os.sep)

        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        script += "Invoke-NetView "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 
        
        script += '| Out-String | %{$_ + \"`n\"};"`nInvoke-Netview completed"'

        return script
