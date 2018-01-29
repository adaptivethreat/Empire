from lib.common import helpers
 
 
class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'ls_m',

            # list of one or more authors for the module
            'Author': ['@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('List contents of a directory'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            # no need to base64 return data
            'OutputExtension': None,

            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                'Link:',
                'http://stackoverflow.com/questions/17809386/howtoconvertastat-output-to-a-unix-permissions-string'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run the module.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Path': {
                'Description'   :   'Path. Defaults to the current directory. This module is mainly for organization. The alias \'ls\' can be used at the agent menu.',
                'Required'      :   True,
                'Value'         :   '.'
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

        filePath = self.options['Path']['Value']
        filePath += '/'

        script = """
try:

    import Foundation
    from AppKit import *
    import os
    import stat
except:
    print "A required module is missing.."

def permissions_to_unix_name(st_mode):
    permstr = ''
    usertypes = ['USR', 'GRP', 'OTH']
    for usertype in usertypes:
        perm_types = ['R', 'W', 'X']
        for permtype in perm_types:
            perm = getattr(stat, 'S_I%%s%%s' %% (permtype, usertype))
            if st_mode & perm:
                permstr += permtype.lower()
            else:
                permstr += '-'
    return permstr

path = "%s"
dirlist = os.listdir(path)

filemgr = NSFileManager.defaultManager()

directoryListString = "\\t\\towner\\tgroup\\t\\tlast modified\\tsize\\t\\tname\\n"

for item in dirlist:
    fullpath = os.path.abspath(os.path.join(path,item))
    attrs = filemgr.attributesOfItemAtPath_error_(os.path.abspath(fullpath), None)
    name = item 
    lastModified = str(attrs[0]['NSFileModificationDate'])
    group = str(attrs[0]['NSFileGroupOwnerAccountName'])
    owner = str(attrs[0]['NSFileOwnerAccountName'])
    size = str(os.path.getsize(fullpath))
    if int(size) > 1024:
        size = int(size) / 1024
        size = str(size) + "K"
    else:
        size += "B"
    perms = permissions_to_unix_name(os.stat(fullpath)[0])
    listString = perms + "  " + owner + "\\t" + group + "\\t\\t" + lastModified.split(" ")[0] + "\\t" + size + "\\t\\t" + name + "\\n"
    if os.path.isdir(fullpath):
        listString = "d"+listString
    else:
        listString = "-"+listString

    directoryListString += listString

print str(os.getcwd())
print directoryListString
""" % filePath

        return script