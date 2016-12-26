// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Portier.Authorization.Tests.Engine
{
    /// <summary>
    /// A generic Role Assignment Provider for testing.
    /// </summary>
    internal class TestRoleAssigmentProvider : IRoleAssignmentProvider
    {
        private IEnumerable<IRoleAssignment> AllRoleAssignment { get; set; }

        private Func<IRoleAssignment, ClaimsIdentity, bool> ByClaimsIdentityFunc { get; set; }

        public TestRoleAssigmentProvider(IEnumerable<IRoleAssignment> allRoleAssignments, Func<IRoleAssignment, ClaimsIdentity, bool> byClaimsIdentityFunc)
        {
            AllRoleAssignment = allRoleAssignments;
            ByClaimsIdentityFunc = byClaimsIdentityFunc;
        }

        public IEnumerable<IRoleAssignment> GetRoleAssignmentsByClaimsIdentity(ClaimsIdentity claimsIdentity)
        {
            return AllRoleAssignment.Where<IRoleAssignment>((roleAssignment) => ByClaimsIdentityFunc(roleAssignment, claimsIdentity));
        }
    }
}