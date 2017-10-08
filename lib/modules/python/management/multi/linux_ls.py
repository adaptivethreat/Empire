from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'linux_ls',

            # list of one or more authors for the module
            'Author': ['@jarrodcoulter'],

            # more verbose multi-line description of the module
            'Description': ('List contents of a directory on Linux OS'),

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
                'Based on the original ls for Mac OS'
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
                'Description'   :   'Path. Defaults to the current directory. This module is mainly for organization. The alias \'ls_lin\' can be used at the agent menu.',
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

    def generate(self):

        filePath = self.options['Path']['Value']
        filePath += '/'

        script = """
try:
    import grp
    import pwd
    import os
    import time
except:
    print "A required module is missing.."

path = "%s"
dirlist = os.listdir(path)

directoryListString = "owner/group\\t\\t\\tlast modified\\t\\t\\tsize\\t\\tname\\n"

for item in dirlist:
    fullpath = os.path.abspath(os.path.join(path,item))
    st = os.stat(fullpath)
    uid = st.st_uid
    gid = st.st_gid
    name = item 
    lastModified = str(time.ctime(os.path.getmtime(fullpath)))
    group = grp.getgrgid(gid)[0]
    owner = pwd.getpwuid(uid)[0]
    size = str(os.path.getsize(fullpath))
    if int(size) > 1024:
        size = int(size) / 1024
        size = str(size) + "K"
    else:
        size += "B"
    listString = owner + "/" + group + "\\t\\t" + lastModified + "\\t" + size + "\\t\\t" + name + "\\n"
    if os.path.isdir(fullpath):
        listString = "d"+listString
    else:
        listString = "-"+listString

    directoryListString += listString

print str(os.getcwd())
print directoryListString
""" % filePath

        return script
