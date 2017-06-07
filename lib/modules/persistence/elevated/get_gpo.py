from lib.common import helpers


class Module:


    def __init__(self, mainMenu, params=[]):
        """Initialise the module."""
        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'get_gpo',

            # list of one or more authors for the module
            'Author': ['Immanuel Willi, Yves Kraft'],

            # more verbose multi-line description of the module
            'Description': ('Read GPOs from Domain Controller. It is possible to read out all GPOs, or only specific ones (by name or GUID).'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # The minimum PowerShell version needed for the module to run
            'MinPSVersion': '2',

            # list of any references/other comments
            # 'Comments': [
            # 'comment',
            # 'http://link/'
            # ]
        }
        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to read GPO information from',
                'Required'      :   True,
                'Value'         :   ''
            },
            'All': {
                'Description'   :   'Set to \'true\' to get information about all existing GPOs',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Name': {
                'Description'   :   'The name of a specific GPO to retrieve information about',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Guid': {
                'Description'   :   'The GUID of a specific GPO to retrieve information about (example: c3b4c360-7865-4407-91e0-0f15a5b8a5c1) ',
                'Required'      :   False,
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

    def generate(self):
        """
        Generate the powershell script.

        the PowerShell script itself, with the command to invoke
        for execution appended to the end. Scripts should output
        everything to the pipeline for proper parsing.
        The script should be stripped of comments, with a link to any
        original reference script included in the comments.
        """
        moduleName = self.info["Name"]

        script = """
            Function ReadGPOs
            {
                [CmdletBinding()]
                Param (
                    [Parameter(Mandatory = $False)]
                    [ValidateNotNullOrEmpty()]
                    [String]
                    $Name,

                    [String]
                    $Guid,

                    [Switch]
                    $All
                )
                if($Name -And $Guid){
                    "Please supply either Guid or the Name of the GPO, but not both!"
                }
                elseif($Name){
                    Get-Gpo -Name $Name
                }
                elseif($Guid){
                    Get-Gpo -Guid $Guid
                }
                elseif($All){
                    Get-Gpo -All
                }
            }

            ReadGPOs"""

        # add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value']:
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        script += ' | Out-String | %{$_ + \"`n\"};"`n' + str(moduleName) + ' completed!"'

        return script
