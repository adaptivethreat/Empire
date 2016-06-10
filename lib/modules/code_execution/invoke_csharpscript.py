import re
from lib.common import helpers
import os
import glob
from os.path import isfile


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-CSharpScript',

            'Author': ['@tristandostaler'],

            'Description': ("Uses PowerShell to execute provided CSharp script. "
                            "It first writes the provided scripts to variable in memory and then compile it. "
                            "Big thanks to https://gallery.technet.microsoft.com/C-Script-Execute-plain-a9eae961 "
                            "I've got rid of the mandatory XML block. Enjoy!"),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'MinPSVersion' : '2',

            'Comments': [
                'https://gallery.technet.microsoft.com/C-Script-Execute-plain-a9eae961'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ScriptsDir' : {
                'Description'   :   'CSharp scripts directory location. All .cs files must be here; not in subdirectory!',
                'Required'      :   True,
                'Value'         :   '/tmp/'
            },
            'Args' : {
                'Description'   :   'Arguments to give to the CSharp script. Space separated. Can be between \"\" if needed.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ConsoleMode' : {
                'Description'   :   'Switch. If True, the program compiles as a console application. If false, like a WinForm application.',
                'Required'      :   False,
                'Value'         :   'True'
            },
            'Debug' : {
                'Description'   :   'Switch. WARNING! If True, not OpsecSafe! If True, the compiled program will open a window to enable debugging.',
                'Required'      :   False,
                'Value'         :   'False'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):

        self.script = ""
        self.filenames = []

        self.directory = self.options['ScriptsDir']['Value']
        self.args = self.options['Args']['Value']
        self.isConsoleMode = self.options['ConsoleMode']['Value'].lower() == 'true'
        self.debugMode = self.options['Debug']['Value'].lower() == 'true'

        self.references = []

        self.recursive_directory_search(self.directory, [])

        self.script += self.get_command(self.filenames, self.isConsoleMode, self.debugMode, self.references)

        self.script += ' csharpscript ' + self.args + '; echo $global:outputVar'

        return self.script

    def recursive_directory_search(self, directory, darray):
        for d in os.listdir(directory):
            if not isfile(os.path.join(directory,d)):
                newlist = darray[:]
                newlist.append(d)
                self.recursive_directory_search(os.path.join(directory,d), newlist)
        for file in glob.glob(directory + "/*.cs"):
            head, tail = os.path.split(file)

            with open(file, 'r') as f:
                filename = ""
                for a in darray:
                    filename += a + "_"
                filename += tail.replace('.','_')
                self.filenames.append(filename)
                self.script += ' $' + filename + ' = @"\n' + str(f.read()).replace('\\n','\n').replace('\\t','\t') + '"@;'
            with open(file, 'r') as f:
                for l in f.readlines():
                    if re.match('^using[\s]+([.a-zA-Z]+);[\s]+',l.replace('\\n','').replace('\\t','')):
                        self.references.append(l.replace('using', '').replace(';','').strip())
                    elif re.match('^namespace',l):
                        break;

    def get_command(self, filenames=[], isConsoleMode=True, debugMode=False, references=[]):
        command = '''$outputVar=""; function writetohost
{
    $global:outputVar = $global:outputVar + $args[0]
    write-host $args[0] -NoNewline
}; function writetoerror
{
    $global:outputVar = $global:outputVar + "`nError: " + $args[0]
    write-host "Error: " + $args[0]
    Write-Error $args[0]
}; function csharpscript
{
<#################################################################################>
<##                                                                             ##>
<##    C#Script - v0.1                                                          ##>
<##                                                                             ##>    
<##    "Execute C# programs as in PowerShell using on-the-fly-compilation       ##> 
<##     and execution"                                                          ##>
<##                                                                             ##>
<##    written by Ingo Karstein                                                 ##>
<##        http://blog.karstein-consulting.com                                  ##>
<##                                                                             ##>
<##    download page on TechNet Gallery                                         ##>
<##        http://gallery.technet.microsoft.com/C-Script-Execute-plain-a9eae961 ##>
<##                                                                             ##>
<##      This script is released under Microsoft Public Licence                 ##>
<##          that can be downloaded here:                                       ##>
<##          http://www.microsoft.com/opensource/licenses.mspx#Ms-PL            ##>
<##                                                                             ##>
<#################################################################################>

$params = $args

#get script path for later use
$csscriptPath = Split-Path (Get-Item -Path ".\" -Verbose).FullName

$CSprogramConfigXML = "<csscript><references>";
        '''
        for r in references:
            command += '$CSprogramConfigXML += "<reference>' + r + '</reference>";'
        
        command += '''
$CSprogramConfigXML += "</references></csscript>";

$CSprogramConfig = $null
try {
    $CSprogramConfig = [xml]$CSprogramConfigXML
} catch {
    $CSprogramConfig = $null
}

if( $CSprogramConfig -eq $null ) {
    writetohost "CONFIG XML AT THE BEGINNING OF THE C# FILE IS INVALID OR MISSING!`n"
    return "-1: CONFIG XML AT THE BEGINNING OF THE C# FILE IS INVALID OR MISSING!`n"
}

$referenceAssembies = @()

$referenceConfig = @("System")
$referenceConfig += $CSprogramConfig.csscript.references.reference

$referenceConfig | % {
    $po = $p = $_
    $n = $null
    try {
        $n = [System.Reflection.AssemblyName]::GetAssemblyName($p)
    } catch {
        $n = $null
    }
    
    if( $n -eq $null ) {
        if( $p -notlike "*.dll") {
            $p += ".dll"
        }

        try {
            $n = [System.Reflection.AssemblyName]::GetAssemblyName($p)
        } catch {
            $n = $null
        }
        if( $n -ne $null ) {
            $p = $n.ToString()
        }
    } else {
        $p = $n.ToString()
    }

    $a = $null
    try { $a = [System.Reflection.Assembly]::ReflectionOnlyLoad($p) } catch { $a = $null } 
    if( $a -eq $null ) {
        try { $a = [System.Reflection.Assembly]::ReflectionOnlyLoadFrom($p) } catch { $a = $null } 
        if( $a -eq $null ) {
            try { $a = [System.Reflection.Assembly]::Load($p) } catch { $a = $null } 
            if( $a -eq $null ) {
                try { $a = [System.Reflection.Assembly]::LoadWithPartialName($po) } catch { $a = $null } 
                if( $a -eq $null ) {
                    try { $a = [System.Reflection.Assembly]::LoadFile($po) } catch { $a = $null } 
                }
            }
        }
    }
    
    if( $a -eq $null ) {
        writetohost "CANNOT LOCATE ASSEMBLY ""$po"".`n"
        return "-1: CANNOT LOCATE ASSEMBLY ""$po"".`n"
    }

    $p = $a.Location
        
    if( ($referenceAssembies | ? { $_ -eq $p} ) -eq $null ) {
        $referenceAssembies += $p
    }
}

if( $PSVersionTable.psversion.major -eq 2 ) {
    $runtime = "3.5"
}
if( $PSVersionTable.psversion.major -eq 3 ) {
    $runtime = "4.0"
}
if( $PSVersionTable.psversion.major -eq 4 ) {
    $runtime = "4.0"
}
if( $PSVersionTable.psversion.major -eq 5 ) {
    $runtime = "4.0"
}
    
if( [System.IntPtr]::Size -eq 8 ) {
    $platform = "x64"
}

if( [System.IntPtr]::Size -eq 4 ) {
    $platform = "x86"
}

if( $CSprogramConfig.csscript.requiredframework -ne $null ) {
    if( $CSprogramConfig.csscript.requiredframework -ne $runtime ) {
        writetohost "THIS PROGRAM REQUIRES FRAMEWORK VERSION ""$($CSprogramConfig.csscript.requiredframework)"".`n"
        return "-1: THIS PROGRAM REQUIRES FRAMEWORK VERSION ""$($CSprogramConfig.csscript.requiredframework)"".`n"
    }
}

if( $CSprogramConfig.csscript.requiredplatform -ne $null ) {
    if( $CSprogramConfig.csscript.requiredplatform -ne $platform ) {
        writetohost "THIS PROGRAM REQUIRES PLATFORM ""$($CSprogramConfig.csscript.requiredplatform)"".`n"
        return "-1: THIS PROGRAM REQUIRES PLATFORM ""$($CSprogramConfig.csscript.requiredplatform)"".`n"
    }
}

if( !$noheader ) {
    writetohost "Framework: $($runtime), Platform: $($platform)`n"
    writetohost "`n"
}

$noconsole = $''' + str(isConsoleMode).lower() + '''

$debug = $''' + str(debugMode).lower() + '''

$compilerCreateOptions = New-Object 'System.Collections.Generic.Dictionary`2[System.string, System.string]'

if( $runtime -notlike "v*") { $runtime = "v$($runtime)" }
$compilerCreateOptions.Add("CompilerVersion", $runtime)

$compilerOptions = $null
try {
    $compilerOptions = (new-object Microsoft.CSharp.CSharpCodeProvider($compilerCreateOptions))
} catch {$compilerOptions = $null }

if( $compilerOptions -eq $null ) {
    writetohost "CANNOT CALL COMPILER. PLEASE CHECK THE 'frameworkversion' SETTINGS.`n"
    return "-1: CANNOT CALL COMPILER. PLEASE CHECK THE 'frameworkversion' SETTINGS.`n"
}

$cp = New-Object System.CodeDom.Compiler.CompilerParameters($referenceAssembies, $null)
$cp.GenerateInMemory = $true
$cp.GenerateExecutable = $false
$cp.CompilerOptions = "/platform:$($platform) /target:$( if($noConsole){'winexe'}else{'exe'}) $(if($debug){"/debug"})"
$cp.IncludeDebugInformation = $debug

if( $debug ) {
    #$cp.TempFiles.TempDir = (split-path $inputFile)
    $cp.TempFiles.KeepFiles = $true
}    

$allCSsourceFiles = @()

        '''
        for f in filenames:
            command += '\n$allCSsourceFiles += $' + f + ';'

        command += '''

try {
    $compilerResults = $compilerOptions.CompileAssemblyFromSource($cp, [String[]]$allCSsourceFiles)
    if( $compilerResults.Errors.Count -gt 0 ) {
        $compilerResults.Errors
        return "-1: " + $compilerResults.Errors
    }
} catch {
    writetohost "CANNOT COMPILE. PLEASE CHECK THE FRAMEWORK VERSION SETTINGS.`n"
    return "-1: CANNOT COMPILE. PLEASE CHECK THE FRAMEWORK VERSION SETTINGS.`n"
}

$ts = $compilerResults.CompiledAssembly.GetTypes()
$m = $ts | % { 
    $t = $_
    $ms = $t.GetMethods("Nonpublic, Static, InvokeMethod, Public, IgnoreCase")
    $ms | ? { $_.Name -eq "Main" } | % {
        $mx = $_    
        if ($mx.ReturnType.Name -eq "Void" -or $mx.ReturnType.Name -like "System.Int*" ) {
            $p = $mx.GetParameters()
            if( $p.Count -eq 1 -and $p.Get(0).ParameterType.Name -like "*String[[]]" ) {
                $mx
            }
            if( $p -eq $null -or $p.Count -eq 0 ) {
                $mx
            }
        }
    }
}

$p = @($null)

$sb = New-Object System.Text.StringBuilder
$w = new-object System.IO.StringWriter($sb)

[System.Console]::SetOut($w)


$objClsName = "cls$([Guid]::NewGuid().ToString("n"))"

$referenceAssembies += @("$($Host.GetType().Assembly.Location)")
$cp2 = New-Object System.CodeDom.Compiler.CompilerParameters($referenceAssembies, $null)
$cp2.GenerateInMemory = $true
$cp2.GenerateExecutable = $false
$cp2.IncludeDebugInformation = $debug
$cp2.TempFiles.KeepFiles = $true

Remove-Variable "compilerResultsErrOut" -Force -Confirm:$false -ErrorAction 0

$types = $null

try {
    $Error.Clear()
    
    $typedef = @"
    using System;
    using System.Threading;
    using System.Collections.Generic;
    using System.Text;
    using System.Management.Automation.Runspaces;
    using System.Reflection;
    
    public class $objClsName
    {
        public System.Reflection.MethodInfo method;
        public string[] prms;
        public ManualResetEvent mre = null;
        public Thread thread = null;
        public bool hasParams = false;
        public System.Management.Automation.Runspaces.Runspace runspace = null;
        public string[] referencedAssemblies = null;
        public SortedList<string, string> foundAssemblies = new SortedList<string, string>();
        
        public $objClsName() 
        {
            AppDomain.CurrentDomain.AssemblyResolve += CurrentDomainOnAssemblyResolve;
        }
        
        private bool _lock = false;
        
        private Assembly CurrentDomainOnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            if( _lock ) return null;

            Assembly asm = null;
            try 
            {
                _lock = true;

                if (foundAssemblies.ContainsKey(args.Name))
                {
                    asm = Assembly.LoadFile(foundAssemblies[args.Name]);
                }

                if (asm == null)
                {
                    try
                    {
                        asm = Assembly.Load(args.Name);
                    }
                    catch
                    {
                        asm = null;
                    }

                    if (asm == null)
                    {
                        foreach (var s in referencedAssemblies)
                        {
                            Assembly tmp = null;

                            try
                            {
                                tmp = Assembly.LoadFile(s);
                                if (!foundAssemblies.ContainsKey(tmp.FullName))
                                {
                                    foundAssemblies.Add(tmp.FullName, tmp.Location);
                                }
                            }
                            catch
                            {
                                tmp = null;
                            }

                            if (tmp != null)
                            {
                                if (tmp.FullName == args.Name)
                                {
                                    asm = tmp;
                                    break;
                                }
                            }
                        }

                        if (asm == null)
                        {
                            foreach (var s in referencedAssemblies)
                            {
                                Assembly tmp = null;

                                System.IO.DirectoryInfo d = new System.IO.DirectoryInfo(System.IO.Path.GetDirectoryName(s));
                                foreach (System.IO.FileInfo f in d.GetFiles("*.dll"))
                                {
                                    try
                                    {
                                        tmp = Assembly.ReflectionOnlyLoadFrom(f.FullName);
                                        if (!foundAssemblies.ContainsKey(tmp.FullName))
                                        {
                                            foundAssemblies.Add(tmp.FullName, tmp.Location);
                                        }
                                    }
                                    catch
                                    {
                                        tmp = null;
                                    }

                                    if (tmp != null)
                                    {
                                        if (tmp.FullName == args.Name)
                                        {
                                            asm = Assembly.LoadFile(f.FullName);
                                            break;
                                        }
                                    }
                                }

                                if (asm != null)
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            } 
            finally 
            {
                _lock = false;
            }

            if( asm != null ) 
            {
                if( !foundAssemblies.ContainsKey(asm.FullName) ) {
                    foundAssemblies.Add(asm.FullName, asm.Location);
                }
            }
            
            return asm;
        }
        
        public void Start(System.Reflection.MethodInfo method, bool hasParams, string[] prms, System.Management.Automation.Runspaces.Runspace r) 
        {   
            $(if($debug) {"System.Diagnostics.Debugger.Launch();System.Diagnostics.Debugger.Break();"})
            this.method = method;
            this.prms = (prms == null ? new string[]{} : prms);
            this.hasParams = hasParams;
            this.runspace = r;
            
            mre = new ManualResetEvent(false);
            
            this.thread = new Thread($objClsName.DoWork);
            thread.Start(this);
        }
        
        public static void DoWork(object data)
        {
            $objClsName obj = ($objClsName)data;

            System.Management.Automation.Runspaces.Runspace.DefaultRunspace = obj.runspace;
            if( obj.hasParams ) 
                obj.method.Invoke(null, new System.Object[]{ obj.prms});
            else
                obj.method.Invoke(null, null);
                
            obj.mre.Set();
        }
        
        public void Stop() 
        {
            if(thread != null ) {
                thread.Abort();
                mre.Set();
                thread = null;
            }
        }
    }    
    
    public class $($objClsName)ConsoleOutput : System.IO.TextWriter 
    {
        public bool IsErrorReceiver = false;

        public event EventHandler<ConsoleOutputEventArgs> WriteEvent;
        public event EventHandler<ConsoleOutputEventArgs> WriteLineEvent;
        
        public class ConsoleOutputEventArgs : EventArgs
        {
            private string _value;
            public string Value { get { return _value; } private set { _value = value; } }
            
            private bool _isError;
            public bool IsError { get { return _isError; } private set { _isError = value; } }
            
            public ConsoleOutputEventArgs(string value, bool isError)
            {
                Value = value;
                IsError = isError;
            }
        }

        public override System.Text.Encoding Encoding { get { return System.Text.Encoding.UTF8; } }
        
        public void InternalWrite(string value)
        {
            if (WriteEvent != null) WriteEvent(this, new ConsoleOutputEventArgs(value, IsErrorReceiver));
        }
        
        public void InternalWriteLine()
        {
            if (WriteLineEvent != null) WriteLineEvent(this, new ConsoleOutputEventArgs("", IsErrorReceiver));
        }

        public override void Write(char value)
        {
            string s = String.Empty;
            s += value;   
            InternalWrite(s);
        }
        
        public override void Write(char[] buffer)
        {
            StringBuilder sb = new StringBuilder(buffer.Length);
            sb.Append(buffer);
            InternalWrite(sb.ToString());
            //base.Write(value);
        }

        public override void Write(char[] buffer, int index, int count)
        {
            StringBuilder sb = new StringBuilder(count);
            sb.Append(buffer, index, count);
            InternalWrite(sb.ToString());
            //base.Write(value);
        }

        public override void Write(bool value)
        {
            InternalWrite(value ? "True" : "False");
        }

        public override void Write(int value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(uint value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(long value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(ulong value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(float value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(double value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(decimal value)
        {
            InternalWrite(value.ToString(this.FormatProvider));
        }

        public override void Write(string value)
        {
            InternalWrite(value);
        }

        public override void Write(object value)
        {
            if (value != null)
            {
                IFormattable formattable = value as IFormattable;
                if (formattable != null)
                {
                    this.InternalWrite(formattable.ToString(null, this.FormatProvider));
                    //base.Write(value);
                    return;
                }
                this.InternalWrite(value.ToString());
            }
        }

        public override void Write(string format, object arg0)
        {
            this.InternalWrite(string.Format(this.FormatProvider, format, new object[]
            {
                arg0
            }));
        }

        public override void Write(string format, object arg0, object arg1)
        {
            this.InternalWrite(string.Format(this.FormatProvider, format, new object[]
            {
                arg0,
                arg1
            }));
        }

        public override void Write(string format, object arg0, object arg1, object arg2)
        {
            this.InternalWrite(string.Format(this.FormatProvider, format, new object[]
            {
                arg0,
                arg1,
                arg2
            }));
        }

        public override void Write(string format, params object[] arg)
        {
            this.Write(string.Format(this.FormatProvider, format, arg));
        }

        public override void WriteLine()
        {
            InternalWriteLine();
        }

        public override void WriteLine(char value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(char[] buffer)
        {
            this.Write(buffer);
            InternalWriteLine();
        }

        public override void WriteLine(char[] buffer, int index, int count)
        {
            this.Write(buffer, index, count);
            InternalWriteLine();
        }

        public override void WriteLine(bool value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(int value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(uint value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(long value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(ulong value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(float value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(double value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(decimal value)
        {
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(string value)
        {
            if (value == null)
            {
                InternalWriteLine();
                return;
            }
            
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(object value)
        {
            if (value == null)
            {
                InternalWriteLine();
                return;
            }
            
            this.Write(value);
            InternalWriteLine();
        }

        public override void WriteLine(string format, object arg0)
        {
            this.WriteLine(string.Format(this.FormatProvider, format, new object[]
            {
                arg0
            }));
        }

        public override void WriteLine(string format, object arg0, object arg1)
        {
            this.WriteLine(string.Format(this.FormatProvider, format, new object[]
            {
                arg0,
                arg1
            }));
        }

        public override void WriteLine(string format, object arg0, object arg1, object arg2)
        {
            this.WriteLine(string.Format(this.FormatProvider, format, new object[]
            {
                arg0,
                arg1,
                arg2
            }));
        }

        public override void WriteLine(string format, params object[] arg)
        {
            this.WriteLine(string.Format(this.FormatProvider, format, arg));
        }
    }        
"@

    $types = Add-Type -CompilerParameters $cp2 -Language CSharp -ErrorVariable "compilerResultsErrOut" -TypeDefinition $typedef -PassThru

    if( $types -eq $null ) {
        writetohost "HELPER CLASS NOT FOUND!`n"
    }
} catch {
}

#stop if compilation of helper class failed
if( $compilerResultsErrOut -ne $null  ){
    $compilerResultsErrOut
    writetohost "CANNOT COMPILE HELPER CLASS.`n"
    return "-1: CANNOT COMPILE HELPER CLASS.`n"
}


#helper object for worker thread
#$helper = Invoke-Expression "new-object ""$objClsName"""
$helper = [System.Activator]::CreateInstance( ($types | ? { $_.Name -eq $objClsName } | select -First 1), $null )
$helper.referencedAssemblies = $referenceAssembies

#console output objects 
$stdOut = [System.Activator]::CreateInstance( ($types | ? { $_.Name -eq "$($objClsName)ConsoleOutput" } | select -First 1), $null ) 

$errOut = [System.Activator]::CreateInstance( ($types | ? { $_.Name -eq "$($objClsName)ConsoleOutput" } | select -First 1), $null ) 
$errOut.IsErrorReceiver = $true

#register console output objects
[System.Console]::SetOut($stdOut)
[System.Console]::SetError($errOut)

$global:outputVar = ""

# event handler for console output
$stdOut.add_WriteEvent( {
    param($sender, $parameter)
    writetohost "$($parameter.Value)"
});

$stdOut.add_WriteLineEvent( {
    param($sender, $parameter)
    writetohost "`n"
});

$errOut.add_WriteEvent( {
    param($sender, $parameter)
    writetoerror "$($parameter.Value)"
});

$errOut.add_WriteLineEvent( { 
    param($sender, $parameter)
    writetoerror ""
});


try {
    $hp = $m.GetParameters().Length -ne 0
    $helper.Start($m, $hp, [Object[]]$params, $host.Runspace)

    while( !($helper.mre.WaitOne(100)) ) {
        #writetohost "Wait..."
    }
} finally {
    $helper.Stop()
}
};
        '''
        return command

