from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Etcd Crawler',

            # list of one or more authors for the module
            'Author': ["@scottjpack",'@TweekFawkes'],

            # more verbose multi-line description of the module
            'Description': ('Pull keys and values from an etcd configuration store'),

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
            'Comments': ["Docs: https://coreos.com/etcd/docs/latest/api.html"]
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
                'Value'         :   'etcd.mesos'
            },
            'Port' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The etcd client communication port, typically 2379 or 1026.',
                'Required'      :   True,
                'Value'         :   '1026'
            },
            'Depth' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'How far into the ETCD hierarchy to recurse.  0 for root keys only, "-1" for no limitation',
                'Required'      :   True,
                'Value'         :   '-1'
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
        target = self.options['Target']['Value']
        #port = self.options['Port']['Value']
	#print str("port: " + port)
        #depth = self.options['Depth']['Value']
	#print str("depth: " + port)
        #if not type(depth) == type(1):
        #    depth = int(depth)
        #if not type(port) == type(1):
        #    port = int(port)
	port = self.options['Port']['Value']
	depth = self.options['Depth']['Value']
	#print str("target: " + target)
	#print str("port: " + port)
	#print str("depth: " + depth)

        script = """
import urllib2
import json

target = "%s"
port = "%s"
depth = "%s"

def get_etcd_keys(target, port, path, depth):
        keys = {}
        resp = urllib2.urlopen("http://" + target + ":" + port + "/v2/keys" + path)
        r = resp.read()
        r = json.loads(r)
        for n in r['node']['nodes']:
                if "dir" in n.keys() and (depth>0):
                        keys.update(get_etcd_keys(target, port, n['key'], depth-1))
                elif "dir" in n.keys() and (depth == -1):
                        keys.update(get_etcd_keys(target, port, n['key'], depth))
                elif "value" in n.keys():
                        keys[n['key']] = n['value']
                else:
                        keys[n['key']] = "directory"
        return keys

def main():
        k = get_etcd_keys(target, port, "/", depth)
        print str(k)

main()


""" % (target, port, depth)

        return script
