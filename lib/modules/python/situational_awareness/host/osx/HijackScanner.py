from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Dylib Hijack Vulnerability Scanner',

            # list of one or more authors for the module
            'Author': ['@patrickwardle','@xorrior'],

            # more verbose multi-line description of the module
            'Description': ('This module can be used to identify applications vulnerable to dylib hijacking on a target system. This has been modified from the original to remove the dependancy for the macholib library.'),

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : None,

            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                'Heavily adapted from @patrickwardle\'s script: https://github.com/synack/DylibHijack/blob/master/scan.py'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run the module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Path' : {
                'Description'   :   'Scan all binaries recursively, in a specific path.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'LoadedProcesses' : {
                'Description'   :   'Scan only loaded process executables',
                'Required'      :   True,
                'Value'         :   'False'
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
        
        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.

        scanPath = self.options['Path']['Value']
        LoadedProcesses = self.options['LoadedProcesses']['Value']

        script = """
from ctypes import *
def run():

    import ctypes
    import os
    import sys
    import shlex
    import subprocess
    import io
    import struct
    from datetime import datetime

    #supported archs
    SUPPORTED_ARCHITECTURES = ['i386', 'x86_64']

    LC_REQ_DYLD = 0x80000000
    LC_LOAD_WEAK_DYLIB = LC_REQ_DYLD | 0x18
    LC_RPATH = (0x1c | LC_REQ_DYLD)
    LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD

    (
        LC_SEGMENT, LC_SYMTAB, LC_SYMSEG, LC_THREAD, LC_UNIXTHREAD, LC_LOADFVMLIB,
        LC_IDFVMLIB, LC_IDENT, LC_FVMFILE, LC_PREPAGE, LC_DYSYMTAB, LC_LOAD_DYLIB,
        LC_ID_DYLIB, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_PREBOUND_DYLIB,
        LC_ROUTINES, LC_SUB_FRAMEWORK, LC_SUB_UMBRELLA, LC_SUB_CLIENT,
        LC_SUB_LIBRARY, LC_TWOLEVEL_HINTS, LC_PREBIND_CKSUM
    ) = range(0x1, 0x18)

    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe

    _CPU_ARCH_ABI64  = 0x01000000

    CPU_TYPE_NAMES = {
        -1:     'ANY',
        1:      'VAX',
        6:      'MC680x0',
        7:      'i386',
        _CPU_ARCH_ABI64  | 7:    'x86_64',
        8:      'MIPS',
        10:     'MC98000',
        11:     'HPPA',
        12:     'ARM',
        13:     'MC88000',
        14:     'SPARC',
        15:     'i860',
        16:     'Alpha',
        18:     'PowerPC',
        _CPU_ARCH_ABI64  | 18:    'PowerPC64',
    }



    #structs that we need

    class mach_header(ctypes.Structure):

        _fields_ = [

            ("magic", ctypes.c_uint),
            ("cputype", ctypes.c_uint),
            ("cpusubtype", ctypes.c_uint),
            ("filetype", ctypes.c_uint),
            ("ncmds", ctypes.c_uint),
            ("sizeofcmds", ctypes.c_uint),
            ("flags", ctypes.c_uint)

        ]

    class mach_header_64(ctypes.Structure):
        _fields_ = mach_header._fields_ + [('reserved',ctypes.c_uint)]

    class load_command(ctypes.Structure):
        _fields_ = [
            ("cmd", ctypes.c_uint),
            ("cmdsize", ctypes.c_uint)
        ]

    #executable binary
    MH_EXECUTE = 2

    #dylib
    MH_DYLIB = 6

    #bundles
    MH_BUNDLE = 8


    LC_Header_Sz = 0x8

    def isSupportedArchitecture(machoHandle):

        #flag
        headersz = 28
        header64sz = 32
        supported = False
        header = ""
        
        #header = mach_header.from_buffer_copy(machoHandle.read())
        try:
            magic = struct.unpack('<L',machoHandle.read(4))[0]
            cputype = struct.unpack('<L',machoHandle.read(4))[0]
            machoHandle.seek(0, io.SEEK_SET)
        
        
            if CPU_TYPE_NAMES.get(cputype) == 'i386':

                header = mach_header.from_buffer_copy(machoHandle.read(headersz))
                supported = True

            elif CPU_TYPE_NAMES.get(cputype) == 'x86_64':

                header = mach_header_64.from_buffer_copy(machoHandle.read(header64sz)) 
                supported = True

            else:
                header = None 
        except:
            pass
            

        return (supported, header)

    def loadedBinaries():

        #list of loaded bins
        binaries = []

        #exec lsof
        lsof = subprocess.Popen('lsof /', shell=True, stdout=subprocess.PIPE)

        #get outpu
        output = lsof.stdout.read()

        #close
        lsof.stdout.close()

        #wait
        lsof.wait()

        #parse/split output
        # ->grab file name and check if its executable
        for line in output.split('\\n'):

            try:

                #split on spaces up to 8th element
                # ->this is then the file name (which can have spaces so grab rest/join)
                binary = ' '.join(shlex.split(line)[8:])

                #skip non-files (fifos etc....) or non executable files
                if not os.path.isfile(binary) or not os.access(binary, os.X_OK):

                    #skip
                    continue

                #save binary
                binaries.append(binary)

            except:

                #ignore
                pass

        #filter out dup's
        binaries = list(set(binaries))
        
        return binaries

    def installedBinaries(rootDirectory = None):

        #all executable binaries
        binaries = []
        
        #init
        if not rootDirectory:

            rootDirectory = '/'

        #recursively walk (starting at r00t)
        for root, dirnames, filenames in os.walk(rootDirectory):

            #check all files
            for filename in filenames:

                #make full
                # ->use realpath to resolve symlinks
                fullName = os.path.realpath(os.path.join(root, filename))

                #skip non-files (fifos etc....)
                if not os.path.isfile(fullName):

                    #skip
                    continue

                #only check executable files
                if os.access(fullName, os.X_OK) and (os.path.splitext(fullName)[-1] == '.dyblib' or os.path.splitext(fullName)[-1] == ''):

                    #save
                    
                    binaries.append(fullName)
        print "Finished with installed binaries\\n"
        return binaries

    def resolvePath(binaryPath, unresolvedPath):

        #return var
        # ->init to what was passed in, since might not be able to resolve
        resolvedPath = unresolvedPath

        #resolve '@loader_path'
        if unresolvedPath.startswith('@loader_path'):

            #resolve
            resolvedPath = os.path.abspath(os.path.split(binaryPath)[0] + unresolvedPath.replace('@loader_path', ''))

        #resolve '@executable_path'
        elif unresolvedPath.startswith('@executable_path'):

            #resolve
            resolvedPath = os.path.abspath(os.path.split(binaryPath)[0] + unresolvedPath.replace('@executable_path', ''))

        return resolvedPath

    def parseBinaries(binaries):

        #dictionary of parsed binaries
        
        parsedBinaries = {}
        #scan all binaries
        for binary in binaries:

            #wrap
            try:

                #try load it (as mach-o)
                f = open(binary, 'rb')
                if not f:

                    #skip
                    continue

            except:

                #skip
                continue

            #check if it's a supported (intel) architecture
            # ->also returns the supported mach-O header
            (isSupported, machoHeader) = isSupportedArchitecture(f)
            if not isSupported:

                #skip
                continue

            #skip binaries that aren't main executables, dylibs or bundles
            if machoHeader.filetype not in [MH_EXECUTE, MH_DYLIB, MH_BUNDLE]:

                #skip
                continue

            #dbg msg
            

            #init dictionary for process
            parsedBinaries[binary] = {'LC_RPATHs': [], 'LC_LOAD_DYLIBs' : [], 'LC_LOAD_WEAK_DYLIBs': [] }

            #save type
            parsedBinaries[binary]['type'] = machoHeader.filetype

            #iterate over all load
            # ->save LC_RPATHs, LC_LOAD_DYLIBs, and LC_LOAD_WEAK_DYLIBs
            
            if CPU_TYPE_NAMES.get(machoHeader.cputype) == 'x86_64':
                f.seek(32, io.SEEK_SET)
            else:
                f.seek(28, io.SEEK_SET) 
            
            
            for cmd in range(machoHeader.ncmds):

                #handle LC_RPATH's
                # ->resolve and save
                
                 #save offset to load commands
                try:
                    lc = load_command.from_buffer_copy(f.read(LC_Header_Sz))
                except Exception as e:
                    break #break out of the nested loop and continue with the parent loop
                size = lc.cmdsize
                if lc.cmd == LC_RPATH:

                    #grab rpath
                    
                    pathoffset = struct.unpack('<L',f.read(4))[0]
                    f.seek(pathoffset - (LC_Header_Sz + 4), io.SEEK_CUR)
                    path = f.read(lc.cmdsize - pathoffset)
                    rPathDirectory = path.rstrip('\\0')

                    #always attempt to resolve '@executable_path' and '@loader_path'
                    rPathDirectory = resolvePath(binary, rPathDirectory)

                    #save
                    parsedBinaries[binary]['LC_RPATHs'].append(rPathDirectory)

                    

                #handle LC_LOAD_DYLIB
                # ->save (as is)
                elif lc.cmd == LC_LOAD_DYLIB:

                    #tuple, last member is path to import
                    
                    pathoffset = struct.unpack('<L',f.read(4))[0]
                    #skip over version and compatibility
                    f.seek(pathoffset - (LC_Header_Sz + 4), io.SEEK_CUR)
                    path = f.read(size - pathoffset)
                    importedDylib = path.rstrip('\\0')

                    #save
                    parsedBinaries[binary]['LC_LOAD_DYLIBs'].append(importedDylib)

                    

                #handle for LC_LOAD_WEAK_DYLIB
                # ->resolve (except for '@rpaths') and save
                elif lc.cmd == LC_LOAD_WEAK_DYLIB:

                    #tuple, last member is path to import
                    
                    pathoffset = struct.unpack('<L',f.read(4))[0]
                    #skip over version and compatibility
                    f.seek(pathoffset - (LC_Header_Sz + 4), io.SEEK_CUR)
                    path = f.read(size - pathoffset)
                    weakDylib = path.rstrip('\\0')

                    #always attempt to resolve '@executable_path' and '@loader_path'
                    weakDylib = resolvePath(binary, weakDylib)

                    #save
                    parsedBinaries[binary]['LC_LOAD_WEAK_DYLIBs'].append(weakDylib)

                    
                else:
                    f.seek(size - LC_Header_Sz, io.SEEK_CUR)
                    
        print "finished parsing load commands"
        return parsedBinaries

    def processBinaries(parsedBinaries):

        #results
        # ->list of dictionaries

        vulnerableBinaries = {'rpathExes': [], 'weakBins': []}

        #scan all parsed binaries
        for key in parsedBinaries:

            #grab binary entry
            binary = parsedBinaries[key]

            #STEP 1: check for vulnerable @rpath'd imports
            # note: only do this for main executables, since dylibs/bundles can share @rpath search dirs w/ main app, etc
            #       which we can't reliably resolve (i.e. this depends on the runtime/loadtime env)

            #check for primary @rpath'd import that doesn't exist
            if binary['type']== MH_EXECUTE and len(binary['LC_RPATHs']):

                #check all @rpath'd imports for the executable
                # ->if there is one that isn't found in a primary LC_RPATH, the executable is vulnerable :)
                for importedDylib in binary['LC_LOAD_DYLIBs']:

                    #skip non-@rpath'd imports
                    if not importedDylib.startswith('@rpath'):

                        #skip
                        continue

                    

                    #chop off '@rpath'
                    importedDylib = importedDylib.replace('@rpath', '')

                    #check the first rpath directory (from LC_RPATHs)
                    # ->is the rpath'd import there!?
                    if not os.path.exists(binary['LC_RPATHs'][0] + importedDylib):

                        #not found
                        # ->means this binary is vulnerable!
                        vulnerableBinaries['rpathExes'].append({'binary': key, 'importedDylib': importedDylib, 'LC_RPATH': binary['LC_RPATHs'][0]})

                        #bail
                        break

            #STEP 2: check for vulnerable weak imports
            # can check all binary types...

            #check binary
            for weakDylib in binary['LC_LOAD_WEAK_DYLIBs']:

                #got to resolve weak @rpath'd imports before checking if they exist
                if weakDylib.startswith('@rpath'):

                    #skip @rpath imports in dylibs and bundles, since they can share @rpath search dirs w/ main app, etc
                    # which we can't reliably resolve (i.e. this depends on the runtime/loadtime env.)
                    if binary['type'] != MH_EXECUTE:

                        #skip
                        continue

                    #skip @rpath imports if binary doesn't have any LC_RPATHS
                    if not len(binary['LC_RPATHs']):

                        #skip
                        continue

                    #chop off '@rpath'
                    weakDylib = weakDylib.replace('@rpath', '')

                    #just need to check first LC_RPATH directory
                    if not os.path.exists(binary['LC_RPATHs'][0] + weakDylib):

                        #not found
                        # ->means this binary is vulnerable!
                        vulnerableBinaries['weakBins'].append({'binary': key, 'weakDylib': weakDylib, 'LC_RPATH': binary['LC_RPATHs'][0]})

                        #bail
                        break

                #path doesn't need to be resolved
                # ->check/save those that don't exist
                elif not os.path.exists(weakDylib):

                    #not found
                    # ->means this binary is vulnerable!
                    vulnerableBinaries['weakBins'].append({'binary': key, 'weakBin': weakDylib})

                    #bail
                    break

        return vulnerableBinaries

    path = "%s"

    ProcBinaries = "%s"
    startTime = datetime.now()
    if ProcBinaries.lower() == "true":
    

        #get list of loaded binaries
        binaries = loadedBinaries()
    elif path :
        #dbg msg
        

        #get list of executable files
        binaries = installedBinaries(path)
    else:
        

        #get list of executable files on the file-system
        binaries = installedBinaries()

    parsedBinaries = parseBinaries(binaries)

    #process/scan em
    vulnerableBinaries = processBinaries(parsedBinaries)

    #display binaries that are vulnerable to rpath hijack
    if len(vulnerableBinaries['rpathExes']):

        #dbg msg
        print '\\nfound %%d binaries vulnerable to multiple rpaths:' %% len(vulnerableBinaries['rpathExes'])

        #iterate over all and print
        for binary in vulnerableBinaries['rpathExes']:

            #dbg msg
            print '%%s has an rpath vulnerability: (%%s%%s)\\n' %% (binary['binary'], binary['LC_RPATH'],binary['importedDylib'])

    #binary didn't have any
    else:

        #dbg msg
        print '\\ndid not find any vulnerable to multiple rpaths'

    #display binaries that are vulnerable to weak import hijack
    if len(vulnerableBinaries['weakBins']):

            #dbg msg
            print '\\nfound %%d binaries vulnerable to weak dylibs:' %% len(vulnerableBinaries['weakBins'])

            #iterate over all and print
            for binary in vulnerableBinaries['weakBins']:

                #dbg msg
                print '%%s has weak import (%%s)\\n' %% (binary['binary'], binary)

    #binary didn't have any
    else:

        #dbg msg
        print '\\ndid not find any missing LC_LOAD_WEAK_DYLIBs'


    #dbg msg
    
    print "Scan completed in " + str(datetime.now() - startTime) + "\\n"

    print "[+] To abuse an rpath vulnerability...\\n"
    print "[+] Find the legitimate dylib: find / -name <dylibname>, and note the path\\n"
    print "[+] Run the CreateHijacker module in /persistence/osx/. Set the DylibPath to the path of the legitimate dylib.\\n"

run()
""" % (scanPath, LoadedProcesses)

        return script
