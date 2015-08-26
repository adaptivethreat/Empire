"""

Misc. helper functions used in Empire.

Includes the PowerShell functions that generate the
randomized stagers.

"""

from time import localtime, strftime
from Crypto.Random import random
import re
import string
import commands
import base64
import binascii
import sys
import os
import socket
import sqlite3
import iptools


###############################################################
#
# Validation methods
#
###############################################################

def validate_hostname(hostname):
    """
    Tries to validate a hostname.
    """
    if len(hostname) > 255: return False
    if hostname[-1:] == ".": hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def validate_ip(IP):
    """
    Uses iptools to validate an IP.
    """
    return iptools.ipv4.validate_ip(IP)


def validate_ntlm(data):

    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    if allowed.match(data):
        return True
    else:
        return False


def generate_ip_list(s):
    """
    Takes a comma separated list of IP/range/CIDR addresses and 
    generates an IP range list.
    """

    # strip newlines and make everything comma separated
    s = ",".join(s.splitlines())
    # strip out spaces
    s = ",".join(s.split(" "))

    ranges = ""
    if s and s != "":
        parts = s.split(",")
        
        for part in parts:
            p = part.split("-")
            if len(p) == 2:
                if iptools.ipv4.validate_ip(p[0]) and iptools.ipv4.validate_ip(p[1]):
                    ranges += "('"+str(p[0])+"', '"+str(p[1])+"'),"
            else:
                if "/" in part and iptools.ipv4.validate_cidr(part):
                    ranges += "'"+str(p[0])+"',"
                elif iptools.ipv4.validate_ip(part):
                    ranges += "'"+str(p[0])+"',"

        if ranges != "":
            return eval("iptools.IpRangeList("+ranges+")")
        else:
            return None
                
    else:
        return None


####################################################################################
#
# Randomizers/obfuscators
#
####################################################################################

def random_string(length=-1, charset=string.ascii_letters):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """
    if length == -1: length = random.randrange(6,16)
    random_string = ''.join(random.choice(charset) for x in range(length))
    return random_string


def obfuscate_num(N, mod):
    """
    Take a number and modulus and return an obsucfated form.

    Returns a string of the obfuscated number N
    """
    d = random.randint(1, mod)
    left = int(N/d)
    right = d
    remainder = N % d
    return "(%s*%s+%s)" %(left, right, remainder)


def randomize_capitalization(data):
    """
    Randomize the capitalization of a string.
    """
    return "".join( random.choice([k.upper(), k ]) for k in data )


def chunks(l, n):
    """
    Generator to split a string l into chunks of size n.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


####################################################################################
#
# Specific PowerShell helpers
#
####################################################################################

def enc_powershell(raw):
    """
    Encode a PowerShell command into a form usable by powershell.exe -enc ...
    """
    return base64.b64encode("".join([char + "\x00" for char in unicode(raw)]))


def powershell_launcher_arch(raw):
    """
    Build a one line PowerShell launcher with an -enc command.
    Architecture independent.
    """
    # encode the data into a form usable by -enc
    encCMD = enc_powershell(raw)

    # get the correct PowerShell path and set it temporarily to %pspath%
    triggerCMD = "if %PROCESSOR_ARCHITECTURE%==x86 (set pspath='') else (set pspath=%WinDir%\\syswow64\\windowspowershell\\v1.0\\)&"
    
    # invoke PowerShell with the appropriate options
    # triggerCMD += "call %pspath%powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc " + encCMD
    triggerCMD += "call %pspath%powershell.exe -NoP -NonI -W Hidden -Enc " + encCMD

    return triggerCMD


def powershell_launcher(raw):
    """
    Build a one line PowerShell launcher with an -enc command.
    """
    # encode the data into a form usable by -enc
    encCMD = enc_powershell(raw)

    return "powershell.exe -NoP -NonI -W Hidden -Enc " + encCMD


def parse_powershell_script(data):
    """
    Parse a raw PowerShell file and return the function names.
    """
    p = re.compile("function(.*){")
    return [x.strip() for x in p.findall(data)]


def strip_powershell_comments(data):
    """
    Strip block comments, line comments, and emtpy lines from a
    PowerShell file.
    """
    
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', data)

    # strip blank lines and lines starting with #
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")))])
    
    return strippedCode


###############################################################
#
# Parsers
#
###############################################################

def parse_mimikatz(data):
    """
    Parse the output from Invoke-Mimikatz to return credential sets.
    """

    # cred format:
    #   credType, domain, username, password, hostname, sid
    creds = []

    # regexes for "sekurlsa::logonpasswords" Mimikatz output
    regexes = ["(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)"]

    hostDomain = ""
    domainSid = ""
    hostName = ""

    lines = data.split("\n")
    for line in lines[0:2]:
        if line.startswith("Hostname:"):
            try:
                domain = line.split(":")[1].strip()
                temp = domain.split("/")[0].strip()
                domainSid = domain.split("/")[1].strip()

                hostName = temp.split(".")[0]
                hostDomain = ".".join(temp.split(".")[1:])
            except:
                pass

    for regex in regexes:

        p = re.compile(regex)

        for match in p.findall(data):

            lines2 = match.split("\n")
            username, domain, password = "", "", ""
            
            for line in lines2:
                try:
                    if "Username" in line:
                        username = line.split(":",1)[1].strip()
                    elif "Domain" in line:
                        domain = line.split(":",1)[1].strip()
                    elif "NTLM" in line or "Password" in line:
                        print line.split(":")
                        password = line.split(":",1)[1].strip()
                except:
                    pass

            if username != "" and password != "" and password != "(null)":
                
                sid = ""

                # substitute the FQDN in if it matches
                if hostDomain.startswith(domain.lower()):
                    domain = hostDomain
                    sid = domainSid

                if validate_ntlm(password):
                    credType = "hash"

                else:
                    credType = "plaintext"

                # ignore machine account plaintexts
                if not (credType == "plaintext" and username.endswith("$")):
                    creds.append((credType, domain, username, password, hostName, sid))

    if len(creds) == 0:
        # check if we have lsadump output to check for krbtgt
        #   happens on domain controller hashdumps
        for x in xrange(8,13):
            if lines[x].startswith("Domain :"):

                domain, sid, krbtgtHash = "", "", ""

                try:
                    domainParts = lines[x].split(":")[1]
                    domain = domainParts.split("/")[0].strip()
                    sid = domainParts.split("/")[1].strip()

                    # substitute the FQDN in if it matches
                    if hostDomain.startswith(domain.lower()):
                        domain = hostDomain
                        sid = domainSid

                    for x in xrange(0, len(lines)):
                        if lines[x].startswith("User : krbtgt"):
                            krbtgtHash = lines[x+2].split(":")[1].strip()
                            break

                    if krbtgtHash != "":
                        creds.append(("hash", domain, "krbtgt", krbtgtHash, hostName, sid))
                except Exception as e:
                    pass

    if len(creds) == 0:
        # check if we get lsadump::dcsync output
        if '** SAM ACCOUNT **' in lines:
            domain, user, userHash, dcName, sid = "", "", "", "", ""
            for line in lines:
                try:
                    if line.strip().endswith("will be the domain"):
                        domain = line.split("'")[1]
                    elif line.strip().endswith("will be the DC server"):
                        dcName = line.split("'")[1].split(".")[0]
                    elif line.strip().startswith("SAM Username"):
                        user = line.split(":")[1].strip()
                    elif line.strip().startswith("Object Security ID"):
                        parts = line.split(":")[1].strip().split("-")
                        sid = "-".join(parts[0:-1])
                    elif line.strip().startswith("Hash NTLM:"):
                        userHash = line.split(":")[1].strip()
                except:
                    pass

            if domain != "" and userHash != "":
                creds.append(("hash", domain, user, userHash, dcName, sid))

    return uniquify_tuples(creds)


###############################################################
#
# Miscellaneous methods (formatting, sorting, etc.)
#
###############################################################

def get_config(fields):
    """
    Helper to pull common database config information outside of the
    normal menu execution.

    Fields should be comma separated.
        i.e. 'version,install_path'
    """

    conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
    conn.isolation_level = None

    cur = conn.cursor()
    cur.execute("SELECT "+fields+" FROM config")
    results = cur.fetchone()
    cur.close()
    conn.close()

    return results


def get_datetime():
    """
    Return the current date/time
    """
    return strftime("%Y-%m-%d %H:%M:%S", localtime())
    

def get_file_datetime():
    """
    Return the current date/time in a format workable for a file name.
    """
    return strftime("%Y-%m-%d_%H-%M-%S", localtime())


def lhost():
    """
    Return the local IP.

    """

    if os.name != "nt":
        import fcntl
        import struct
        def get_interface_ip(ifname):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                return socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(),
                        0x8915,  # SIOCGIFADDR
                        struct.pack('256s', ifname[:15])
                    )[20:24])
            except IOError as e:
                return ""

    ip = ""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        pass
    except:
        print "Unexpected error:", sys.exc_info()[0]
        return ip

    if (ip == "" or ip.startswith("127.")) and os.name != "nt":
        interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                if ip != "":
                    break
            except:
                print "Unexpected error:", sys.exc_info()[0]
                pass
    return ip

def color(string, color=None, graphic=''):
    """
    Change text color for the Linux terminal.

    Args:
        string (str): String to colorify
        color (str): Color to colorify the string in the following list:
            black, red, green, yellow, blue, purple, cyan, gr[ae]y
        graphic (str): Graphic to append to the beginning of the line
    """

    colors = {
    'normal'         : "\x1b[0m",
    'black'          : "\x1b[30m",
    'red'            : "\x1b[31m",
    'green'          : "\x1b[32m",
    'yellow'         : "\x1b[33m",
    'blue'           : "\x1b[34m",
    'purple'         : "\x1b[35m",
    'cyan'           : "\x1b[36m",
    'grey'           : "\x1b[90m",
    'gray'           : "\x1b[90m",
    'bold'           : "\x1b[1m"
    }

    if not color:
        if string.startswith("[!] "): color = 'red'
        if string.startswith("[+] "): color = 'green'
        if string.startswith("[*] "): color = 'blue'

    if color not in colors:
        print colors['red'] + 'Color not found: {}'.format(color) + colors['normal']
        return

    if color:
        return colors[color] + graphic + string + colors['normal']
    else:
        return string + colors['normal']

def output(string):
    print color(string)

def success(string):
    print color(string, color="green", graphic='[+] ')

def warning(string):
    print color(string, color="blue", graphic='[*] ')

def error(string):
    print color(string, color="red", graphic='[!] ')


def unique(seq, idfun=None):
    # uniquify a list, order preserving
    # from http://www.peterbe.com/plog/uniqifiers-benchmark
    if idfun is None:
        def idfun(x): return x
    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)
        # in old Python versions:
        # if seen.has_key(marker)
        # but in new ones:
        if marker in seen: continue
        seen[marker] = 1
        result.append(item)
    return result


def uniquify_tuples(tuples):
    # uniquify mimikatz tuples based on the password
    # cred format- (credType, domain, username, password, hostname, sid)
    seen = set()
    return [item for item in tuples if "%s%s%s%s"%(item[0],item[1],item[2],item[3]) not in seen and not seen.add("%s%s%s%s"%(item[0],item[1],item[2],item[3]))]


def urldecode(url):
    """
    URL decode a string.
    """
    rex=re.compile('%([0-9a-hA-H][0-9a-hA-H])',re.M)
    return rex.sub(htc,url)


def decode_base64(data):
    """
    Try to decode a base64 string.
    From http://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
    """
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += b'='* missing_padding

    try:
        result = base64.decodestring(data)
        return result
    except binascii.Error:
        # if there's a decoding error, just return the data
        return data


def encode_base64(data):
    """
    Decode data as a base64 string.
    """
    return base64.encodestring(data).strip()


def complete_path(text, line, arg=False):
    """
    Helper for tab-completion of file paths.
    """

    # stolen from dataq at
    #   http://stackoverflow.com/questions/16826172/filename-tab-completion-in-cmd-cmd-of-python

    if arg:
        # if we have "command something path"
        argData = line.split()[1:]
    else:
        # if we have "command path"
        argData = line.split()[0:]
    
    if not argData or len(argData) == 1:
        completions = os.listdir('./')
    else:
        dir, part, base = argData[-1].rpartition('/')
        if part == '':
            dir = './'
        elif dir == '':
            dir = '/'            

        completions = []
        for f in os.listdir(dir):
            if f.startswith(base):
                if os.path.isfile(os.path.join(dir,f)):
                    completions.append(f)
                else:
                    completions.append(f+'/')

    return completions

def tableify(data, headers=None):
    '''ASCII table for a list of strings

    Args:
        data (list of lists): List of lists for each row of data
        headers (list) optional: List of column names

    Return:
        None
    '''
    from itertools import izip_longest

    if not isinstance(data, list):
        return ''
    if headers and not isinstance(headers, list):
        headers = [headers]
    if headers:
        data = [headers] + data

    # Example color in order to pad for colors
    red = "\x1b[31m"
    table = []
    
    columns = izip_longest(*data, fillvalue='')
    widths = []
    for column in columns:
        new_row = []
        # Need to be a string in order to get length
        column = [str(item) for item in column]
        max_len = len(max(column, key=len))
        max_len = max(max_len, len(red)*2)
        widths.append(max_len)
        for item in column:
            new_row.append(item.ljust(max_len, ' '))
        table.append(new_row)

    table = izip_longest(*table)

    result = []
    result.append('+' + '+'.join(['-' * (width+2) for width in widths]) + '+')
    result.append('| ' + ' | '.join(table.next()) + ' |')
    result.append('+' + '+'.join(['-' * (width+2) for width in widths]) + '+')

    for row in table:
        result.append('  ' + '   '.join(row) + '  ')

    # result.append('+' + '+'.join(['-' * (width+2) for width in widths]) + '+')

    for line in result:
        print line
