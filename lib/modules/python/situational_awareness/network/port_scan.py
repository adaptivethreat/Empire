from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Port Scanner.',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': ('Simple Port Scanner.'),

            # True if the module needs to run in the background
            'Background' : True,

            # File extension to save the file as
            'OutputExtension' : None,

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['CIDR Parser credits to http://bibing.us.es/proyectos/abreproy/12106/fichero/ARCHIVOS%252Fservidor_xmlrpc%252Fcidr.py']
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
            },
            'Target' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Targets to scan in single, range 0-255 or CIDR format.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Port' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The port to scan for.',
                'Required'      :   True,
                'Value'         :   '8080'
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
        target = self.options['Target']['Value']
        port = self.options['Port']['Value']
        

        script = """
import socket

iplist = []


def iprange(addressrange): # converts a ip range into a list
    first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
    for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
        iplist.append(first3octets+str(i))
    return iplist

def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b


def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s


def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]


def printCIDR(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])

    if subnet == 32:
        print bin2ip(baseIP)

    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            iplist.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return


def validateCIDRBlock(b):

    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        print "Error: Invalid CIDR format!"
        return False

    prefix, subnet = b.split("/")

    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            print "Error: quad "+str(q)+" wrong size."
            return False

    if (int(subnet) < 1) or (int(subnet) > 32):
        print "Error: subnet "+str(subnet)+" wrong size."
        return False

    return True


def portscan(target,port):

    try:  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((target, port))
    except Exception:
        failvar = 0
        print "Host {} {}/tcp closed".format(target, port)
    else:
        print "Host {} {}/tcp open".format(target, port)
    s.close()


def main(target, port):
    
    if '/' in target:
        printCIDR(target)
        for ip in iplist:
            portscan(ip, port)
    elif '-' in target:
        iprange(target)
        for ip in iplist:
            portscan(ip, port)
    else:
        portscan(target, port)

target = "%s"
port = %s

main(target, port)

""" %(target, port)

        return script