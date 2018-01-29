from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-SystemDNSServer',

            'Author': ['DarkOperator'],

            'Description': ('Enumerates the DNS Servers used by a system.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1'
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

        script = """

function Get-SystemDNSServer
{
    <#
    .Synopsis
       Enumerates the DNS Servers used by a system
       Part of Posh-SecMod (https://github.com/darkoperator/Posh-SecMod/)
       Author: darkoperator

    .DESCRIPTION
       Enumerates the DNS Servers used by a system returning an IP Address .Net object for each.
    .EXAMPLE
       C:\> Get-SystemDNSServer
        Address            : 16885952
        AddressFamily      : InterNetwork
        ScopeId            :
        IsIPv6Multicast    : False
        IsIPv6LinkLocal    : False
        IsIPv6SiteLocal    : False
        IsIPv6Teredo       : False
        IsIPv4MappedToIPv6 : False
        IPAddressToString  : 192.168.1.1
    #>
    $DNSServerAddresses = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    foreach($interface in $interfaces)
    {
        if($interface.OperationalStatus -eq "Up")
        {
            $DNSConfig = $interface.GetIPProperties().DnsAddresses
            if (!$DNSConfig.IsIPv6SiteLocal)
            {
                $DNSServerAddresses += $DNSConfig
            }
        }
    }
    $DNSServerAddresses
} Get-SystemDNSServer"""

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value']) 
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
