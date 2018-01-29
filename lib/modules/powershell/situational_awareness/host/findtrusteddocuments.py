from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Find-TrustedDocuments',

            # list of one or more authors for the module
            'Author': ['@jamcut'],

            # more verbose multi-line description of the module
            'Description': ('This module will enumerate the appropriate registry '
                            'keys to determine what, if any, trusted documents '
                            'exist on the host.  It will also enumerate trusted locations.'
                            ),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',

            # list of any references/other comments
            'Comments': [
                'Original .ps1 file',
                'https://github.com/jamcut/one-offs/blob/master/Find-TrustedDocuments.ps1'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to enumerate trusted documents from.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        # the PowerShell script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.   

        moduleSource = self.mainMenu.installPath + "/data/module_source/situational_awareness/host/Find-TrustedDocuments.ps1"
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

        script = moduleCode
        scriptEnd = "Find-TrustedDocuments"
        if obfuscate:
            scriptEnd = helpers.obfuscate(self.mainMenu.installPath, psScript=scriptEnd, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
