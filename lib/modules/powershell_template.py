from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Invoke-Something',

            # List of one or more authors for the module
            'Author': ['@yourname'],

            # More verbose multi-line description of the module
            'Description': ('description line 1 '
                            'description line 2'),

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
                'http://link/'
            ]
        }

        # Any options needed by the module, settable during runtime
        self.options = {
            # Format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description':   'Agent to grab a screenshot from.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'Command': {
                'Description':   'Command to execute',
                'Required'   :   True,
                'Value'      :   'test'
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
        moduleSource = self.mainMenu.installPath + "/data/module_source/..."
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
        script = """
function Invoke-Something {

}
Invoke-Something"""

        scriptEnd = ""

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
