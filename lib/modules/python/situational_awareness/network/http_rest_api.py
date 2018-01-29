from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'HTTP REST API',

            # list of one or more authors for the module
            'Author': ['@TweekFawkes',"@scottjpack"],

            # more verbose multi-line description of the module
            'Description': ('Interacts with a HTTP REST API and returns the results back to the screen.'),

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
            'Comments': ["Docs: https://mesos.github.io/chronos/docs/api.html", "urllib2 DELETE method credits to: http://stackoverflow.com/questions/21243834/doing-put-using-python-urllib2"]
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
            'Protocol' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Protocol or Scheme to use.',
                'Required'      :   True,
                'Value'         :   'http'
            },
            'Target' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'FQDN, domain name, or hostname of the remote target.',
                'Required'      :   True,
                'Value'         :   'master.mesos'
            },
            'Port' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The port to connect to.',
                'Required'      :   True,
                'Value'         :   '8123'
            },
            'Path' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The path.',
                'Required'      :   True,
                'Value'         :   '/v1/version'
            },
            'RequMethod' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The HTTP request method to use.',
                'Required'      :   True,
                'Value'         :   'GET'
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
        protocol = self.options['Protocol']['Value']
        target = self.options['Target']['Value']
        port = self.options['Port']['Value']
        path = self.options['Path']['Value']
        requmethod = self.options['RequMethod']['Value']

        script = """
import urllib2

protocol = "%s"
target = "%s"
port = "%s"
path = "%s"
requmethod = "%s"

url = protocol + "://" + target + ":" + port + path

class MethodRequest(urllib2.Request):
    def __init__(self, *args, **kwargs):
        if 'method' in kwargs:
            self._method = kwargs['method']
            del kwargs['method']
        else:
            self._method = None
        return urllib2.Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        if self._method is not None:
            return self._method
        return urllib2.Request.get_method(self, *args, **kwargs)

try:
    request = MethodRequest(url, method=requmethod)
    request.add_header('User-Agent',
                   'Mozilla/6.0 (X11; Linux x86_64; rv:24.0) '
                   'Gecko/20140205     Firefox/27.0 Iceweasel/25.3.0')
    opener = urllib2.build_opener(urllib2.HTTPHandler)
    content = opener.open(request).read()
    print str(content)
except Exception as e:
    print "Failure sending payload: " + str(e)

print "Finished"
""" %(protocol, target, port, path, requmethod)

        return script
