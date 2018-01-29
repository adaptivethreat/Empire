from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'RemoveLaunchDaemon',

            # list of one or more authors for the module
            'Author': ['@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('Remove an Empire Launch Daemon.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # if the module needs administrative privileges
            'NeedsAdmin' : True,

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
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'PlistPath' : {
                'Description'   :   'Full path to the plist file to remove.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ProgramPath' : {
                'Description'   :   'Full path to the bash script/ binary file to remove.',
                'Required'      :   True,
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
        
        plistpath = self.options['PlistPath']['Value']
        programpath = self.options['ProgramPath']['Value']



        script = """
import subprocess 

process = subprocess.Popen('launchctl unload %s', stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('rm %s', stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('rm %s', stdout=subprocess.PIPE, shell=True)
process.communicate()

print "\\n [+] %s has been removed"
print "\\n [+] %s has been removed"
""" %(plistpath,plistpath,programpath,plistpath,programpath)

        return script
