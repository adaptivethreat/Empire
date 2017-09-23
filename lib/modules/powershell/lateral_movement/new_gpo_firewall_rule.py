from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        # Metadata info about the module, not modified during runtime
        self.info = {
            # Name for the module that will appear in module menus
            'Name': 'NewGpo_Firewall_Rule',

            # List of one or more authors for the module
            'Author': ['Yves Kraft (@nrx_ch), Immanuel Willi'],

            # More verbose multi-line description of the module
            'Description': ("This module is intended to set a Windows Firewall Rule using Group Policy Objects (GPO). "
                            "It creates a new (or modifies an existing) GPO on the Domain Controller. "
                            "Options for linking and enabling GPOs can be provided if required. "
                            "Requirements: This module needs Domain Admin privileges, and needs to be run against a Domain Controller!"
                            "The deployed GPO will change the Firewalls settings on a client after up to 90 Minutes, or immediatley when executing the invokeGPUpdate module."),

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
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to read GPO information from',
                'Required'      :   True,
                'Value'         :   ''
            },
            'GpoName' : {
                'Description'   :   'Either the module creates a new GPO with the given name, or extends an existing GPO (i.e. "Default Domain Policy"). The default value is a random string.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LinkGpo' : {
                'Description'   :   'Link GPO to domain',
                'Required'      :   False,
                'Value'         :   'Yes'
            },
            'EnforceGpo' : {
                'Description'   :   'Enforce GPO. Possible values "yes" or "no"',
                'Required'      :   False,
                'Value'         :   'Yes'
            },
            'RuleName' : {
                'Description'   :   'Specifies that only matching firewall rules of the indicated name are created. This parameter acts just like a file name in that only one rule with a given name may exist in a policy store at a time. During group policy processing and policy merge, rules that have the same name but come from multiple stores being merged will overwrite one another so that only one exists.',
                'Required'      :   True,
                'Value'         :   'New_FWRule'
            },
            'RuleDisplayName' : {
                'Description'   :   'Specifies that only matching firewall rules of the indicated display name are created. Wildcard characters are accepted. Specifies the localized, user-facing name of the firewall rule being created.',
                'Required'      :   True,
                'Value'         :   'New_FWRule DisplayName'
            },
            'Direction' : {
                'Description'   :   'Specifies that matching firewall rules of the indicated direction are created. This parameter specifies which direction of traffic to match with this rule. The acceptable values for this parameter are: "Inbound" or "Outbound".',
                'Required'      :   True,
                'Value'         :   'Inbound'
            },
            'Protocol' : {
                'Description'   :   'Specifies that network packets with matching IP addresses match this rule. The acceptable values for this parameter are: "TCP" or "UDP"',
                'Required'      :   True,
                'Value'         :   'TCP'
            },
            'LocalAddress' : {
                'Description'   :   'Specifies that network packets with matching IP addresses match this rule. This parameter value is the first endpoint of an IPsec rule and specifies the computers that are subject to the requirements of this rule. This parameter value is an IPv4 or IPv6 address, hostname, subnet, range, or Any.',
                'Required'      :   False,
                'Value'         :   'Any'
            },
            'LocalPort' : {
                'Description'   :   'Specifies that network packets with matching IP local port numbers match this rule. The acceptable value is a port, range, or keyword and depends on the protocol. If the Protocol parameter value is TCP or UDP, then the acceptable values for this parameter are: Port range: 0 through 65535, Port number: 80 or "Any". ',
                'Required'      :   False,
                'Value'         :   '1337'
            },
            'Profile' : {
                'Description'   :   'Specifies one or more profiles to which the rule is assigned. The rule is active on the local computer only when the specified profile is currently active. Only one profile is applied at a time. The acceptable values for this parameter are: "Any", "Domain", "Private", "Public"',
                'Required'      :   True,
                'Value'         :   'Any'
            },
            'RemoteAddress' : {
                'Description'   :   'Specifies that network packets with matching IP addresses match this rule. This parameter value is the second endpoint of an IPsec rule and specifies the computers that are subject to the requirements of this rule. This parameter value is an IPv4 or IPv6 address, hostname, subnet, range, or Any. ',
                'Required'      :   False,
                'Value'         :   'Any'
            },
            'RemotePort' : {
                'Description'   :   'Specifies that network packets with matching IP port numbers match this rule. This parameter value is the second endpoint of an IPsec rule. The acceptable value is a port, range, or keyword and depends on the protocol. If the protocol is TCP or UDP, then the acceptable values for this parameter are: Port range: 0 through 65535, Port number: 80 or "Any". ',
                'Required'      :   False,
                'Value'         :   'Any'
            },
            'Action' : {
                'Description'   :   'Specifies that matching firewall rules of the indicated action are created. This parameter specifies the action to take on traffic that matches this rule. The acceptable values for this parameter are: Allow or Block.',
                'Required'      :   False,
                'Value'         :   'Allow'
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
                # parameter format is [Name, Value]
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
Function new_Firewall_Rule
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
        $LinkGpo,

        [String]
        $EnforceGpo,

        [String]
        $RuleName,

        [String]
        $RuleDisplayName,

        [String]
        $Direction,

        [String]
        $Protocol,

        [String]
        $LocalAddress,

        [String]
        $LocalPort,

        [String]
        $Profile,

        [String]
        $RemoteAddress,

        [String]
        $RemotePort,

        [String]
        $Action,

        [String]
        $ADSpath
    )

    if ($GpoName -eq ""){
        $GpoName=(([char[]]([char]'a'..[char]'z') + 0..9 | sort {get-random})[0..31] -join '')
    }

    #Convert ADSPath to Domain "DC=corp,DC=com" -> "corp.com"
    $Domain=$ADSPath -Replace ",DC=","."
    $Domain=$Domain -Replace "DC=",""
    $Store=$Domain+'\\'+$GpoName

    New-GPO -Name $GpoName
    $GPOSession = Open-NetGPO -PolicyStore $Store

    New-NetFirewallRule -name $RuleName -DisplayName $RuleDisplayName -Direction $Direction -Protocol $Protocol -LocalPort $LocalPort -LocalAddress $LocalAddress -RemoteAddress $RemoteAddress -RemotePort $RemotePort -Profile $Profile -GPOSession $GPOSession
    Save-NetGPO -GPOSession  $GPOSession

    if ($LinkGpo.ToLower() -eq "yes"){
        New-GPLink -Name $GpoName -Target $ADSpath -Enforced Yes -LinkEnabled $LinkGpo
    }

}

new_Firewall_Rule"""

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
