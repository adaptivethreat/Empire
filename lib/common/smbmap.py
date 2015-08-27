#! /usr/bin/env python2
import sys
import uuid
import signal
import string
import time
import random
import string
import logging
import ConfigParser
import argparse
from threading import Thread
from impacket import smb, version, smb3, nt_errors, smbserver
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *
from impacket.dcerpc import transport, svcctl, srvsvc
from collections import defaultdict
import ntpath
import cmd
import os
import re

# A lot of this code was taken from Impacket's own examples
# https://impacket.googlecode.com
# Seriously, the most amazing Python library ever!!
# Many thanks to that dev team

class RemoteShell():
    def __init__(self, share, rpc, mode, serviceName, command):
        self.__share = share
        self.__mode = mode
        # self.__output = '\\Windows\\Temp\\' + 'output'
        # self.__batchFile = '%TEMP%\\' + 'output.bat'
        # self.__outputBuffer = ''
        self.__command = command
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc

        dce = rpc.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            raise e

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        
        try:
            dce.bind(svcctl.MSRPC_UUID_SVCCTL)
            self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
            resp = self.rpcsvc.OpenSCManagerW()
            self.__scHandle = resp['ContextHandle']
            self.transferClient = rpc.get_smb_connection()
        except Exception as e:
            print "[!] {}".format(e)

    def set_copyback(self):
        s = self.__rpc.get_smb_connection()
        s.setTimeout(100000)
        myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
        self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

    def finish(self):
        # Just in case the service is still created
        try:
           dce = self.__rpc.get_dce_rpc()
           dce.connect()
           dce.bind(svcctl.MSRPC_UUID_SVCCTL)
           self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
           resp = self.rpcsvc.OpenSCManagerW()
           self.__scHandle = resp['ContextHandle']
           resp = self.rpcsvc.OpenServiceW(self.__scHandle, self.__serviceName)
           service = resp['ContextHandle']
           self.rpcsvc.DeleteService(service)
           self.rpcsvc.StopService(service)
           self.rpcsvc.CloseServiceHandle(service)
        except Exception, e:
            print '[!]', e
            pass

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data
        
        if self.__mode == 'SHARE':
            while True:
                try:
                    # print "Getting output file: {}".format(self.__output)
                    self.transferClient.getFile(self.__share, self.__output, output_callback)
                    break
                except Exception as e:
                    print(str(e))
                    if "OBJECT_NAME_NOT_FOUND" in str(e):
                        print "Output file not created yet, waiting.."
                        time.sleep(2)
                        pass
                    if "SUCCESS" in str(e):
                        break
                    else:
                        raise e
                        
            # print "Deleting output file: {}".format(self.__output)
            self.transferClient.deleteFile(self.__share, self.__output)

        else:
            print "Output file: {}".format(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)
            with open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r') as f:
                output_callback(fd.read())

            # os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data, execute_only=False):
        if execute_only:
            command = self.__shell + data
        else:
            command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
            if self.__mode == 'SERVER':
                self.set_copyback()
                command += ' & ' + self.__copyBack
                command += ' & ' + 'del ' + self.__batchFile
                command += ' & ' + 'del ' + self.__output
            else:
                command += ' & ' + 'del ' + self.__batchFile

        resp = self.rpcsvc.CreateServiceW(self.__scHandle, self.__serviceName, self.__serviceName, command.encode('utf-16le'))
        service = resp['ContextHandle']
        try:
           self.rpcsvc.StartServiceW(service)
        except Exception as e:
            pass
        self.rpcsvc.DeleteService(service)
        self.rpcsvc.CloseServiceHandle(service)
        # print "Output file before getting: {}".format(self.__output)
        if not execute_only:
            self.get_output()

    def send_data(self, data, disp_output = True, execute_only=False):
        self.execute_remote(data, execute_only)
        return True

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, protocols = None, username = '', password = '', domain = '', hashes = None, share = None, command = None, disp_output = True):
        if not protocols:
            protocols = PSEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__serviceName = self.service_generator().encode('utf-16le')
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__mode  = 'SHARE'
        self.__command = command
        self.__disp_output = disp_output
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def service_generator(self, size=6, chars=string.ascii_uppercase):
        return ''.join(random.choice(chars) for _ in range(size))

    def run(self, addr, execute_only=False):
        result = ''
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            try:
                self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName, self.__command)
                result = self.shell.send_data(self.__command, self.__disp_output, execute_only)
            except SessionError as e:
                if 'STATUS_SHARING_VIOLATION' in str(e):
                    return

                print 'Exception', str(e)
                return str(e)

        return result

class SMBMap():
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }

    def __init__(self):
        self.recursive = False
        self.list_files = False
        self.smbconn = {}
        self.isLoggedIn = False
        self.pattern = None
        self.hosts = {}
        self.jobs = {}
        self.search_output_buffer = ''
     
    def login(self, host, username, password, domain, verbose=False):
        try:
            self.smbconn[host] = SMBConnection(host, host, sess_port=445, timeout=2)
            self.smbconn[host].login(username, password, domain=domain)
             
            if verbose:
                if self.smbconn[host].isGuestSession() > 0:
                    print '[+] Guest SMB session established on %s...' % (host)
                else:
                    print '[+] User SMB session established on %s...' % (host)
            return True

        except Exception as e:
            self.smbconn.pop(host, None)
            return False
 
    def logout(self, host):
        self.smbconn[host].logoff()
        
    def smart_login(self, curr_host=None):
        success = False
        for host in self.hosts:
            if self.is_ntlm(self.hosts[host]['passwd']):
                print '[+] Hash detected, using pass-the-hash to authentiate'
                if self.hosts[host]['port'] == 445: 
                    success = self.login_hash(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
                else:
                    success = self.login_rpc_hash(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
            else:
                if self.hosts[host]['port'] == 445:
                    success = self.login(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
                else:
                    success = self.login_rpc(host, self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'])
            
            if not success:
                print '[!] Authentication error on %s' % (host)
                self.smbconn.pop(host,None)
                self.hosts.pop(host, None)

                return success
            
    def login_rpc_hash(self, host, username, ntlmhash, domain):
        lmhash, nthash = ntlmhash.split(':')    
    
        try:
            self.smbconn[host] = SMBConnection('*SMBSERVER', host, sess_port=139, timeout=2)
            self.smbconn[host].login(username, '', domain, lmhash=lmhash, nthash=nthash)
            
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest RPC session established on %s...' % (host)
            else:
                print '[+] User RPC session establishd on %s...' % (host) 
            return True

        except Exception as e:
            print '[!] RPC Authentication error occured'
            return False
 
    def login_rpc(self, host, username, password, domain):
        try:
            self.smbconn[host] = SMBConnection('*SMBSERVER', host, sess_port=139, timeout=2)
            self.smbconn[host].login(username, password, domain)
            
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest RPC session established on %s...' % (host)
            else:
                print '[+] User RPC session establishd on %s...' % (host) 
            return True
        
        except Exception as e:
            print '[!] RPC Authentication error occured'
            return False
 
    def login_hash(self, host, username, ntlmhash, domain):
        lmhash, nthash = ntlmhash.split(':')    
        try:
            self.smbconn[host] = SMBConnection(host, host, sess_port=445, timeout=2)
            self.smbconn[host].login(username, '', domain, lmhash=lmhash, nthash=nthash)
            
            if self.smbconn[host].isGuestSession() > 0:
                print '[+] Guest session established on %s...' % (host)
            else:
                print '[+] User session establishd on %s...' % (host)
            return True

        except Exception as e:
            print '[!] Authentication error occured'
            print '[!]', e
            return False
 
    def find_open_ports(self, address, port):    
        result = 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((address,port))
            if result == 0:
                sock.close()
                return True
        except:
            return False

    def start_file_search(self, host, pattern, share, search_path):
        job_name = str(uuid.uuid4().get_hex())[0:24]
        try:
            tmp_dir = self.exec_command(host, share, 'echo %TEMP%', False).strip()
            if len(tmp_dir) == 0:
                tmp_dir = 'C:\\'
            ps_command = 'powershell -command "Start-Process cmd -ArgumentList """"/c """"""""findstr /R /S /M /P /C:""""""""%s"""""""" %s\*.* 2>nul > %s\%s.txt"""""""" """" -WindowStyle hidden"' % (pattern, search_path, tmp_dir, job_name)
            success = self.exec_command(host, share, ps_command, False)
            self.jobs[job_name] = { 'host' : host, 'share' : share, 'tmp' : tmp_dir , 'pattern' : pattern}
            print '[+] Job %s started on %s, result will be stored at %s\%s.txt' % (job_name, host, tmp_dir, job_name)
        except Exception as e:
            print e
            print '[!] Job creation failed on host: %s' % (host)

    def get_search_results(self):
        print '[+] Grabbing search results, be patient, share drives tend to be big...'
        counter = 0
        while counter != len(self.jobs.keys()):
            try:
                for job in self.jobs.keys():
                    result = self.exec_command(self.jobs[job]['host'], self.jobs[job]['share'], 'cmd /c "2>nul (>>%s\%s.txt (call )) && (echo not locked) || (echo locked)"' % (self.jobs[job]['tmp'], job), False)
                    if 'not locked' in result:
                        dl_target = '%s%s\%s.txt' % (self.jobs[job]['share'], self.jobs[job]['tmp'][2:], job)
                        host_dest = self.download_file(host, dl_target, False)
                        results_file = open(host_dest)
                        self.search_output_buffer += 'Host: %s \t\tPattern: %s\n' % (self.jobs[job]['host'], self.jobs[job]['pattern'])
                        self.search_output_buffer += results_file.read()
                        os.remove(host_dest)
                        self.delete_file(host, dl_target, False)
                        counter += 1
                        print '[+] Job %d of %d completed' % (counter, len(self.jobs.keys()))
                    else:
                        time.sleep(10)
            except Exception as e:
                print e
        print '[+] All jobs complete'
        print self.search_output_buffer 
                    
    def list_drives(self, host, share):
        counter = 0
        disks = []
        local_disks = self.exec_command(host, share, 'fsutil fsinfo drives', False)
        net_disks_raw = self.exec_command(host, share, 'net use', False)
        net_disks = ''
        for line in net_disks_raw.split('\n'):
            if ':' in line:
                data = line.split(' ')
                data = filter(lambda a: a != '', data)
                for item in data:
                    counter += 1
                    net_disks += '%s\t\t' % (item)
                    if '\\' in item:
                        net_disks += ' '.join(data[counter:])
                        break
                disks.append(net_disks)
                net_disks = ''
        print '[+] Host %s Local %s' % (host, local_disks.strip())
        print '[+] Host %s Net Drive(s):' % (host)
        if len(disks) > 0:
            for disk in disks:
                 print '\t%s' % (disk)
        else:
            print '\tNo mapped network drives'
        pass    
        
    def output_shares(self, host, lsshare, lspath, verbose=True):
        shareList = [lsshare] if lsshare else self.get_shares(host)
        shares = defaultdict(list)
        for share in shareList:
            error = 0
            pathList = {}
            canWrite = False

            try:
                root = string.replace('/%s' % (PERM_DIR),'/','\\')
                # root = ntpath.normpath(root)
                # self.create_dir(host, share, root)
                # shares['readwrite'].append(share)
                # canWrite = True
                # shares.append('{}[R/W]'.format(share))
                # try:
                    # self.remove_dir(host, share, root)
                # except:
                    # print '\t[!] Unable to remove test directory at \\\\%s\\%s%s, plreae remove manually' % (host, share, root)
            except Exception as e:
                #print e
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                #print(exc_type, fname, exc_tb.tb_lineno)
                sys.stdout.flush()
                canWrite = False

            if canWrite == False:
                readable = self.list_path(host, share, '', self.pattern, False)
                if readable:
                    shares['readonly'].append(share)
                else:
                    error += 1
            
            if error == 0: 
                path = '/'
                if self.list_files and not self.recursive:
                    if lsshare and lspath:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, lsshare)
                        dirList = self.list_path(host, lsshare, lspath, self.pattern, verbose)
                        sys.exit()
                    else:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, share)
                        dirList = self.list_path(host, share, path, self.pattern, verbose)
                
                if self.recursive:
                    if lsshare and lspath:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, lsshare)
                        dirList = self.list_path_recursive(host, lsshare, lspath, '*', pathList, self.pattern, verbose)
                        sys.exit()
                    else:
                        if self.pattern:
                            print '\t[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, share)
                        dirList = self.list_path_recursive(host, share, path, '*', pathList, self.pattern, verbose)
            
            if error > 0:
                shares['noaccess'].append(share)

        return shares


    def get_shares(self, host):
        shareList = self.smbconn[host].listShares()
        shares = []
        for item in range(len(shareList)):
            shares.append(shareList[item]['shi1_netname'][:-1])
        return shares 

    def list_path_recursive(self, host, share, pwd, wildcard, pathList, pattern, verbose):
        root = self.pathify(pwd)
        root = ntpath.normpath(root)
        width = 16
        try:
            pathList[root] = self.smbconn[host].listPath(share, root)
            if verbose: 
                print '\t.%s' % (root.strip('*'))

            if len(pathList[root]) > 2:
                    for smbItem in pathList[root]:
                        try:
                            filename = smbItem.get_longname()
                            isDir = 'd' if smbItem.is_directory() > 0 else '-' 
                            filesize = smbItem.get_filesize() 
                            readonly = 'w' if smbItem.is_readonly() > 0 else 'r'
                            date = time.ctime(float(smbItem.get_mtime_epoch()))
                            if smbItem.is_directory() <= 0:
                                fileMatch = re.search(pattern.lower(), filename.lower())
                                if fileMatch:
                                    dlThis = '%s\\%s/%s' % (share, pwd, filename)
                                    dlThis = dlThis.replace('/', '\\')
                                    print '\t[+] Match found! Downloading: %s' % (ntpath.normpath(dlThis))
                                    self.download_file(host, dlThis, False) 
                            if verbose: 
                                print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
                        except SessionError as e:
                            print '[!]', e
                            continue
                        except Exception as e:
                            print '[!]', e
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            sys.stdout.flush()
                    for smbItem in pathList[root]:
                        try:
                            filename = smbItem.get_longname()
                            if smbItem.is_directory() > 0 and filename != '.' and filename != '..':
                                subPath = '%s/%s' % (pwd, filename)
                                subPath = self.pathify(subPath)
                                pathList[subPath] = self.smbconn[host].listPath(share, subPath)
                                if len(pathList[subPath]) > 2:
                                    self.list_path_recursive(host, share, '%s/%s' % (pwd, filename), wildcard, pathList, pattern, verbose)

                        except SessionError as e:
                            continue
        except Exception as e:
            pass

    def pathify(self, path):
        root = ntpath.join(path,'*')
        root = root.replace('/','\\')
        #root = ntpath.normpath(root)
        return root

    def list_path(self, host, share, path, pattern, verbose=False, only_output=False):
        '''
        List shares and regex search for files in the shares to download

        If only_output, will not try to download
        '''
        pwd = self.pathify(path)
        width = 16
        try:
            output_file = True
            pathList = self.smbconn[host].listPath(share, pwd)
            if verbose:
                print '\t.%s' % (path.ljust(50))
            if only_output:
                if not pathList:
                    return []
                return pathList
            for item in pathList:
                filesize = item.get_filesize() 
                readonly = 'w' if item.is_readonly() > 0 else 'r'
                date = time.ctime(float(item.get_mtime_epoch()))
                isDir = 'd' if item.is_directory() > 0 else 'f'
                filename = item.get_longname()
                if item.is_directory() <= 0:
                    print pattern.lower(), filename.lower()
                    fileMatch = re.search(pattern.lower(), filename.lower())
                    if fileMatch:
                        dlThis = '%s\\%s/%s' % (share, ntpath.normpath(pwd.strip('*')), filename)
                        dlThis = dlThis.replace('/','\\') 
                        print '\t[+] Match found! Downloading: %s' % (dlThis)
                        output_file = self.download_file(host, dlThis, True) 
                if verbose:
                    print '\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(width), date, filename)
            return output_file
        except Exception as e:
            # import traceback; traceback.print_exc()
            return []
 
    def create_dir(self, host, share, path):
        #path = self.pathify(path)
        self.smbconn[host].createDirectory(share, path)

    def remove_dir(self, host, share, path):
        #path = self.pathify(path)
        self.smbconn[host].deleteDirectory(share, path)
    
    def valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def filter_results(self, pattern):
        pass
    
    def download_file(self, host, path, verbose=True):
        path = path.replace('/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]   
        share = path.split('\\')[0]
        path = path.replace(share, '')
        dlpath = ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_'))))
        print dlpath
        if os.path.exists(dlpath):
            print "Continueing, already downloaded {}".format(dlpath)
            return
        try:
            out = open(ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))),'wb')
            dlFile = self.smbconn[host].listPath(share, path)
            if verbose:
                msg = '[+] Starting download: %s (%s bytes)' % ('%s%s' % (share, path), dlFile[0].get_filesize())
                if self.pattern:
                    msg = '\t' + msg
                print msg 
            self.smbconn[host].getFile(share, path, out.write)
            if verbose:
                msg = '[+] File output to: %s/%s' % (os.getcwd(), ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))))
                if self.pattern:
                    msg = '\t'+msg
                print msg 
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print '[!] Error retrieving file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                print '[!] Error retrieving file, invalid path'
            elif 'STATUS_SHARING_VIOLATION' in str(e):
                if not verbose:
                    indent = '\t'
                else:
                    indent = ''
                print '%s[!] Error retrieving file %s, sharing violation' % (indent, filename)
                out.close()
                os.remove(ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share.replace('$',''), path.replace('\\','_')))))
        except Exception as e:
            print '[!] Error retrieving file, unkown error'
            os.remove(filename)
        out.close()
        return '%s/%s' % (os.getcwd(), ntpath.basename('%s/%s' % (os.getcwd(), '%s-%s%s' % (host, share, path.replace('\\','_')))))
    
    def exec_command(self, host, share, command, disp_output = True, execute_only=False):
        if self.is_ntlm(self.hosts[host]['passwd']):
            hashes = self.hosts[host]['passwd']
        else:
            hashes = None 
        executer = CMDEXEC('445/SMB', self.hosts[host]['user'], self.hosts[host]['passwd'], self.hosts[host]['domain'], hashes, share, command, disp_output)
        result = executer.run(host, execute_only)
        if disp_output:
            print result
        return result
 
    def delete_file(self, host, path, verbose=True):
        path = path.replace('/','\\')
        path = ntpath.normpath(path)
        filename = path.split('\\')[-1]   
        share = path.split('\\')[0]
        path = path.replace(share, '')
        path = path.replace(filename, '')
        try:
            self.smbconn[host].deleteFile(share, path + filename)
            if verbose:
                print '[+] File successfully deleted: %s%s%s' % (share, path, filename)
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                if verbose:
                    print '[!] Error deleting file, access denied'
            elif 'STATUS_INVALID_PARAMETER' in str(e):
                if verbose:
                    print '[!] Error deleting file, invalid path'
            elif 'STATUS_SHARING_VIOLATION' in str(e):
                if verbose:
                    print '[!] Error retrieving file, sharing violation'
            else:
                print '[!] Error deleting file %s%s%s, unkown error' % (share, path, filename)
                print '[!]', e
        except Exception as e:
            print '[!] Error deleting file %s%s%s, unkown error' % (share, path, filename)
            print '[!]', e
         
    def upload_file(self, host, src, dst): 
        dst = string.replace(dst,'/','\\')
        dst = ntpath.normpath(dst)
        dst = dst.split('\\')
        share = dst[0]
        dst = '\\'.join(dst[1:])
        if os.path.exists(src):
            print '[+] Starting upload: %s (%s bytes)' % (src, os.path.getsize(src))
            upFile = open(src, 'rb')
            try:
                self.smbconn[host].putFile(share, dst, upFile.read)
                print '[+] Upload complete' 
            except Exception as e:
                print '[!]', e
                print '[!] Error uploading file, you need to include destination file name in the path'
            upFile.close() 
        else:
            print '[!] Invalid source. File does not exist'
            sys.exit()

    def is_ntlm(self, password):
        try:
            if len(password.split(':')) == 2:
                lm, ntlm = password.split(':')
                if len(lm) == 32 and len(ntlm) == 32:
                    return True
                else: 
                    return False
        except Exception as e:
            return False

    def get_version(self, host):
        try:
            rpctransport = transport.SMBTransport(self.smbconn[host].getServerName(), self.smbconn[host].getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smbconn[host])
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrServerGetInfo(dce, 102)
            
            print "Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major']
            print "Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor']
            print "Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name']
            print "Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment']
            print "Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath']
            print "Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users']
        except Exception as e:
            print '[!] RPC Access denied...oh well'
            print '[!]', e
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            sys.exit()

def signal_handler(signal, frame):
    print 'You pressed Ctrl+C!'
    sys.exit(1)
