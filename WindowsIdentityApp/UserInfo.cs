using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;

namespace WindowsIdentityApp
{
    class UserInfo
    {
        private string domain, username, userGroupName;
        private List<Domain> domainList;
        private List<string> groupList;
        public void GetUserAdUserInfo(out string username, out string userGroupName, out string domain)
        {
            groupList = new List<string>();
            Console.WriteLine("Create WindowsIdentity");
            Console.Write("Enter the name of the domain on which to log on: ");
            domain = Console.ReadLine();
            Console.Write("Enter the login of a user on {0} that you wish to impersonate: ", domain);
            username = Console.ReadLine();
            Console.Write("Enter the Group for {0}: ", username);
            userGroupName = Console.ReadLine();
        }

        public void GetAdGroups()
        {
            try
            {
                GetUserAdUserInfo(out username, out userGroupName, out domain);
                string sAMAccount = "sAMAccount = " + username;
                DirectoryEntry ad = new DirectoryEntry("LDAP://" + domain);
                domainList = new List<Domain>(GetUserDomains(ad, sAMAccount));
            }
            catch (Exception e)
            {
                Console.Write(e);
                Console.Write(" \n \n Type 'q' to quit: ");
                var q = Console.ReadLine();
                if (q.Equals("q"))
                    Environment.Exit(0);
            }
        }

        public List<Domain> GetUserDomains(DirectoryEntry ad, string sAMAccount)
        {
            //Method Unused, now using a new way to access AD User groups
            var searchedDomains = new List<Domain>();
            try
            {
                ad.RefreshCache(new[] { "canonicalName", "objectSid", "distinguishedName" });
                var userCN = (string)ad.Properties["canonicalName"].Value;
                var domainDns = userCN.Substring(0, userCN.IndexOf("/", StringComparison.Ordinal));
                DirectorySearcher directorySearcher = new DirectorySearcher(ad);
                directorySearcher.Filter = sAMAccount;
                directorySearcher.PropertiesToLoad.Add("canonicalName");
                var userDn = (string)ad.Properties["distinguishedName"].Value;
                var domainFull = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domain));
                foreach (Domain domain in domainFull.Forest.Domains)
                {
                    Console.Write("\n Domain Name: {0} ", domain.Name);
                    searchedDomains.Add(domain);
                    using (var context = new PrincipalContext(ContextType.Domain,domain.Name))
                    {
                        using (var user = new UserPrincipal(context))
                        {
                            PrincipalSearchResult<Principal> tempGroupResults =  user.GetAuthorizationGroups();
                            user.SamAccountName = username;
                            using (PrincipalSearcher searcher = new PrincipalSearcher(user))
                            {
                                foreach (var result in searcher.FindAll())
                                {
                                    UserPrincipal userResult = result as UserPrincipal;
                                    if (userResult != null)
                                    {
                                        try
                                        {
                                            PrincipalSearchResult<Principal> userGroupResults = userResult.GetAuthorizationGroups();
                                            foreach (Principal group in userGroupResults)
                                            {
                                                groupList.Add(group.Name);
                                                Console.Write("\n User Group: {0}", group);
                                            }
                                        }
                                        catch (Exception e)
                                        {
                                            Console.Write(e);
                                            Console.Write(" \n \n Type 'q' to quit: ");
                                            if (Console.ReadLine().Equals("q"))
                                                Environment.Exit(0);
                                        }

                                    }
                                }
                            }
                        }
                    }
                }
                Console.Write(" \n \n Type 'q' to quit: ");
                var q = Console.ReadLine();
                if (q.Equals("q"))
                    Environment.Exit(0);
                return searchedDomains;
            }
            catch (Exception e)
            {
                Console.Write(e);
                Console.Write(" \n \n Type 'q' to quit: ");
                var q = Console.ReadLine();
                if (q.Equals("q"))
                    Environment.Exit(0);
            }
            return searchedDomains;
        }
    }
}
