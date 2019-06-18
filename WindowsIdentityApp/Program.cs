using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace WindowsIdentityApp
{
    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
        int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);
        // Test harness.
        // If you incorporate this code into a DLL, be sure to demand FullTrust.
        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]
        static void Main(string[] args)
        {
            SafeTokenHandle safeTokenHandle;
            try
            {
                const int LOGON32_PROVIDER_DEFAULT = 0;
                //This parameter causes LogonUser to create a primary token.
                const int LOGON32_LOGON_INTERACTIVE = 2;
                string userName, domainName;
                Console.Write("Enter the name of the domain on which to log on: ");
                domainName = Console.ReadLine();

                Console.Write("Enter the login of a user on {0} that you wish to impersonate: ", domainName);
                userName = Console.ReadLine();

                Console.Write("Enter the password for {0}: ", userName);
                bool returnValue = LogonUser(userName, domainName, Console.ReadLine(),
                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                out safeTokenHandle);
                Console.WriteLine("Did LogonUser Succeed? " + (returnValue ? "Yes" : "No"));
                if (!returnValue)
                {
                    int ret = Marshal.GetLastWin32Error();
                    Console.WriteLine("LogonUser failed with error code : {0}", ret);
                    //Added this Win32 to grab more informative information on error
                    Win32Exception innerException = new Win32Exception(ret);
                    Console.WriteLine("WIN 32 Exception: {0}", innerException);
                    throw new System.ComponentModel.Win32Exception(ret);
                }

                Console.WriteLine("Current User before impersonation: {0}", WindowsIdentity.GetCurrent().Name);
                using (WindowsIdentity newId = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                {
                    using (WindowsImpersonationContext impersonatedUser = newId.Impersonate())
                    {
                        var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
                        Console.WriteLine("Current User after impersonation: {0}", WindowsIdentity.GetCurrent().Name);
                        List<string> claimNames = new List<string>();
                        foreach (var claim in WindowsIdentity.GetCurrent().Claims.Where(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"))
                        {
                            var sid = new SecurityIdentifier(claim.Value);
                            var name = sid.Translate(typeof(NTAccount));
                            Console.WriteLine(name.Value);
                            claimNames.Add(name.Value);
                        }
                        foreach (var name in claimNames)
                        {
                            Console.WriteLine($"In Claim '{name}':: {principal.IsInRole(name)}");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.Write(e);
            }
            finally
            {
                Console.Write(" \n \n Type 'q' to quit: ");
                var q = Console.ReadLine();
                if (q.Equals("q"))
                    Environment.Exit(0);
            }
        }
        public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeTokenHandle() : base(true){}

            [DllImport("kernel32.dll")]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [SuppressUnmanagedCodeSecurity]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }
    }
}
