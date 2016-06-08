import re
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-CSharpScript',

            'Author': ['@tristandostaler'],

            'Description': ("Uses PowerShell to execute provided CSharp script. "
                            "It first writes the provided scripts on $env:/TEMP/scriptName.cs and then compile it. "
                            "Big thanks to https://gallery.technet.microsoft.com/C-Script-Execute-plain-a9eae961"
                            "The info to build the script must be put in an XML block. See website for more info."),

            'Background' : True,

            'OutputExtension' : None,

            'NeedsAdmin' : False,

            'OpsecSafe' : False,

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
                'Description'   :   'CSharp scripts directory location.',
                'Required'      :   True,
                'Value'         :   '/tmp/'
            },
            'MainProgramName' : {
                'Description'   :   'The name of the main program to execute. It is this one that must define the XML block.',
                'Required'      :   True,
                'Value'         :   'Program.cs'
            },
            'Args' : {
                'Description'   :   'Arguments to give to the CSharp script. Space separated and between \"\"',
                'Required'      :   False,
                'Value'         :   ''
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

        import os
        import glob

        script = self.get_command()

        directory = self.options['ScriptsDir']['Value']
        mainProgram = self.options['MainProgramName']['Value']
        args = self.options['Args']['Value']

        for file in glob.glob(directory + "/*.cs"):
            head, tail = os.path.split(file)

            with open(file, 'r') as f:
                script += ' @"\n' + str(f.read()).replace('\\n','\n').replace('\\t','\t') + '"@ | Out-File "$env:TEMP\\' + tail + '";'

        script += ' csharpscript "$env:TEMP\\' + mainProgram + '" ' + args

        return script

    def get_command(self):
        return '''function csharpscript
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

#get C# program filename
#  when starting the path with "*" no C#Script headers will be printed.
$CSprogram = $args[0]

#toggle "quiet" mode
if( $CSprogram.StartsWith("*") ) {
    $CSprogram = $CSprogram.Remove(0,1)
    $noheader = $true
} else {
    Write-Host "C#Script v0.1 by Ingo Karstein (http://blog.karstein-consulting.com)"
    Write-Host ""
    $noheader = $false
}

#get all other parameters
$params = $args | select -Skip 1

#get script path for later use
$csscriptPath = Split-Path (Get-Item -Path ".\" -Verbose).FullName

##Used through development
#$CSprogram="c:\source2\csscript\testwin\testwin\program.cs" 
#$CSprogram="c:\source2\csscript\test\test\program.cs" 
#$debug=$true

#get full name of C# program file
$CSprogram = (new-object System.IO.FileInfo($CSprogram)).FullName

#test C# program file exists
if( !(Test-Path $CSprogram -PathType Leaf) ) {
    Write-Host "SCRIPT NOT FOUND! ($CSprogram)"
    return -1
}


#load C# program
$CSprogramContent = Get-Content $CSprogram


#load config xml at the beginning of the C# program
<# sample:
//<csscript>
//  <nodebug/>                                 <!--optional--> 
//  <references>
//    <reference>System</reference>
//    <reference>System.Core</reference>
//    <reference>System.Data</reference>
//    <reference>System.Data.DataSetExtensions</reference>
//    <reference>System.Xml</reference>
//    <reference>System.Xml.Linq</reference>
//    <reference>System.Windows.Forms</reference>
//  </references>
//  <mode>winexe</mode>
//  <requiredframework>4.0</requiredframework> <!--optional-->
//  <requiredplatform>x64</requiredplatform>   <!--optional-->
//  <files>
//      <file>Form1.cs</file>
//      <file>Form1.Designer.cs</file>
////      <file>Test</file>                    <!--comment!!-->
//  </files>
//</csscript>

#4 slash characters means "comment" => line not used.
#In "reference" you can use also full paths. There is no relative path support at the moment.
#mode = winexe / exe 
#"files" can be relative to the C# program file.
#>

$CSprogramConfigXML = "";
foreach($l in $CSprogramContent) {
    if( !([string]::IsNullOrEmpty($l.Trim())) -and $l -notlike "//*" ) { break }
    
    if( $l -notlike "////*") {
        if( !([string]::IsNullOrEmpty($l.Trim())) ) {
            $CSprogramConfigXML += $l.remove(0,2)
        }
    }
}

$CSprogramConfig = $null
try {
    $CSprogramConfig = [xml]$CSprogramConfigXML
} catch {
    $CSprogramConfig = $null
}

if( $CSprogramConfig -eq $null ) {
    Write-Host "CONFIG XML AT THE BEGINNING OF THE C# FILE IS INVALID OR MISSING!"
    return -1
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
        write-host "CANNOT LOCATE ASSEMBLY ""$po""."
        return -1
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
        Write-Host "THIS PROGRAM REQUIRES FRAMEWORK VERSION ""$($CSprogramConfig.csscript.requiredframework)""."
        return -1
    }
}

if( $CSprogramConfig.csscript.requiredplatform -ne $null ) {
    if( $CSprogramConfig.csscript.requiredplatform -ne $platform ) {
        Write-Host "THIS PROGRAM REQUIRES PLATFORM ""$($CSprogramConfig.csscript.requiredplatform)""."
        return -1
    }
}

if( !$noheader ) {
    Write-Host "Framework: $($runtime), Platform: $($platform)"
    Write-Host ""
}

$noconsole = $false
if( $CSprogramConfig.csscript.mode -ne $null) {
    $n = $CSprogramConfig.csscript.mode
    if( $n -ne "exe" -and $n -ne "winexe" ) {
        Write-Host "UNKNOWN ""MODE"" IN CONFIG XML INSIDE C# FILE."
    }
    $noconsole = $n -eq "winexe"
}

$debug = ( $CSprogramConfig.csscript.debug -ne $null) 

#$type = ('System.Collections.Generic.Dictionary`2') -as "Type"
#$type = $type.MakeGenericType( @( ("System.String" -as "Type"), ("system.string" -as "Type") ) )
#$compilerCreateOptions = [Activator]::CreateInstance($type)
$compilerCreateOptions = New-Object 'System.Collections.Generic.Dictionary`2[System.string, System.string]'

if( $runtime -notlike "v*") { $runtime = "v$($runtime)" }
$compilerCreateOptions.Add("CompilerVersion", $runtime)

$compilerOptions = $null
try {
    $compilerOptions = (new-object Microsoft.CSharp.CSharpCodeProvider($compilerCreateOptions))
} catch {$compilerOptions = $null }

if( $compilerOptions -eq $null ) {
    Write-Host "CANNOT CALL COMPILER. PLEASE CHECK THE 'frameworkversion' SETTINGS."
    return -1
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
$allCSsourceFiles += [string]::Join("`n", $CSprogramContent)

try {
    Push-Location
    
    Set-Location (Split-Path $CSprogram)
    [System.Environment]::CurrentDirectory = Get-Location
    
    if( $CSprogramConfig.csscript.files.file -ne $null ) {
        $CSprogramConfig.csscript.files.file | % {
            $p = $_
            $p = (new-object System.IO.FileInfo($p)).FullName

            if( Test-Path $p -PathType Leaf ) {
                $allCSsourceFiles += [System.IO.File]::ReadAllText($p)
            }
        }
    }
} finally {
    Pop-Location
    [System.Environment]::CurrentDirectory = Get-Location
}

try {
    $compilerResults = $compilerOptions.CompileAssemblyFromSource($cp, [String[]]$allCSsourceFiles)
    if( $compilerResults.Errors.Count -gt 0 ) {
        $compilerResults.Errors
        return -1
    }
} catch {
    Write-Host "CANNOT COMPILE. PLEASE CHECK THE FRAMEWORK VERSION SETTINGS."
    return -1
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
        Write-Host "HELPER CLASS NOT FOUND!"
    }
} catch {
}

#stop if compilation of helper class failed
if( $compilerResultsErrOut -ne $null  ){
    $compilerResultsErrOut
    Write-Host "CANNOT COMPILE HELPER CLASS."
    return -1
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

# event handler for console output
$stdOut.add_WriteEvent( {
    param($sender, $parameter)

    write-host "$($parameter.Value)" -NoNewline 
});

$stdOut.add_WriteLineEvent( {
    param($sender, $parameter)
    write-host ""
});

$errOut.add_WriteEvent( {
    param($sender, $parameter)

    Write-Error "$($parameter.Value)"
});

$errOut.add_WriteLineEvent( { 
    param($sender, $parameter)
});


try {
    $hp = $m.GetParameters().Length -ne 0
    $helper.Start($m, $hp, [Object[]]$params, $host.Runspace)

    while( !($helper.mre.WaitOne(100)) ) {
        #Write-Host "Wait..."
    }
} finally {
    $helper.Stop()
}
};
        '''

