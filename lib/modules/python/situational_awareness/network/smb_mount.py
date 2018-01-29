class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'SMB Mount',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': 'This module will attempt mount an smb share and execute a command on it.',

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
                'Description'   :   'Agent to run on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Domain' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Domain',
                'Required'      :   False,
                'Value'         :   ''
            },
            'UserName' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Username',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Password',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ShareName' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Share to mount. e.g. 192.168.1.1/c$',
                'Required'      :   True,
                'Value'         :   ''
            },
            'MountPoint' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Directory to mount on target.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Command' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Command to run.',
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

        domain = self.options['Domain']['Value']
        username = self.options['UserName']['Value']
        password = self.options['Password']['Value']
        sharename = self.options['ShareName']['Value']
        mountpoint = self.options['MountPoint']['Value']
        command = self.options['Command']['Value']

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        script = """
import sys, os, subprocess, re

username = "%s"
domain = "%s"
password = "%s"
sharename = "%s"
mountpoint = "%s"
command = "%s"
password.replace('!','%%21')
password.replace('#','%%23')
password.replace('$','%%24')


cmd = \"""mkdir /Volumes/{}\""".format(mountpoint)
subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

cmd1 = \"""mount_smbfs //'{};{}:{}'@{} /Volumes/{}""\".format(domain,username,password,sharename,mountpoint)
print subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE).stdout.read()
print ""

cmd2 = \"""{} /Volumes/{}""\".format(command,mountpoint)
print subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE).stdout.read()
print ""



print ""
print subprocess.Popen('diskutil unmount force /Volumes/{}', shell=True, stdout=subprocess.PIPE).stdout.read().format(mountpoint)
print ""
print "Finished"




""" % (username, domain, password, sharename, mountpoint, command)
        return script
