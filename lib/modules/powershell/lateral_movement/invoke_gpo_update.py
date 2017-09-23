from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'invokeGPUpdate',

            # List of one or more authors for the module
            'Author': ['Yves Kraft (@nrx_ch)', 'Immanuel Willi'],

            # More verbose multi-line description of the module
            'Description': ("This module invokes a immediate update of Group Policies."),

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
            # Format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent with Domain Admin privileges on a Domain Controller.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Force' : {
                'Description'   :   'Reapplies all policy settings. By default, Group Policy is only refreshed when policy settings have changed.',
                'Required'      :   False,
                'Value'         :   'No'
            },
            'RandomDelayInMinutes' : {
                'Description'   :   'Specifies the delay, in minutes that Task Scheduler will wait, with a random factor added to lower the network load, before running a scheduled Group Policy refresh. Delay from 0 minutes to a maximum of 44640 minutes (31 days)',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'Filter' : {
                'Description'   :   'Specifies the filter for the computers for which to schedule a Group Policy refresh',
                'Required'      :   False,
                'Value'         :   '*'
            },
            'ADSpath' : {
                'Description'   :   'Specify the LDAP distinguished name of the site, domain or OU to which to link the GPO (e.g. for corp.com, the LDAP distinguished name is "DC=corp,DC=com)".',
                'Required'      :   False,
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

Function invokeGPUpdate
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [String]
        $Force,

        [Int]
        $RandomDelayInMinutes,

        [String]
        $Filter,

        [String]
        $ADSpath
        )

        $Computers=Get-ADComputer -SearchBase $ADSpath -Filter $Filter
        if ($Force.ToLower() -eq "yes") { $Computers | ForEach-Object -Process {Invoke-GPUpdate -Computer $_.Name -RandomDelayInMinutes $RandomDelayInMinutes -Force} }
        else { $Computers | ForEach-Object -Process {Invoke-GPUpdate -Computer $_.Name -RandomDelayInMinutes $RandomDelayInMinutes} }
}

invokeGPUpdate"""

        # Add any arguments to the end execution of the script
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # If we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])
        script += ' | Out-String | %{$_ + \"`n\"};"`n' + str(moduleName) + ' completed!"'

        return script
