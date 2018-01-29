from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-PacketCapture',

            'Author': ['@obscuresec', '@mattifestation'],

            'Description': ('Starts a packet capture on a host using netsh.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://obscuresecurity.blogspot.com/p/presentation-slides.html',
                'http://blogs.msdn.com/b/canberrapfe/archive/2012/03/31/capture-a-network-trace-without-installing-anything-works-for-shutdown-and-restart-too.aspx'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'MaxSize' : {
                'Description'   :   'Maximum size of capture file. Blank for no limit.',
                'Required'      :   True,
                'Value'         :   '100MB'
            },
            'TraceFile' : {
                'Description'   :   'File to log the capture out to.',
                'Required'      :   True,
                'Value'         :   'C:\\capture.etl'
            },
            'Persistent' : {
                'Description'   :   'Switch. Persist capture across reboots.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'StopTrace' : {
                'Description'   :   'Switch. Stop trace capture.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        maxSize = self.options['MaxSize']['Value']
        traceFile = self.options['TraceFile']['Value']
        persistent = self.options['Persistent']['Value']
        stopTrace = self.options['StopTrace']['Value']

        if stopTrace.lower() == "true":
            script = "netsh trace stop"

        else:
            script = "netsh trace start capture=yes traceFile=%s" %(traceFile)

            if maxSize != "":
                script += " maxSize=%s" %(maxSize)

            if persistent != "":
                script += " persistent=yes"
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
