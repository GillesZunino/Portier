// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

namespace Portier.Authorization.Tests
{
    /// <summary>
    /// A generic Role Assignment for testing.
    /// </summary>
    internal class TestRoleAssignment : IRoleAssignment
    {
        public string Id { get; internal set; }

        public string RoleDefinitionId { get; internal set; }

        public string Scope { get; internal set; }

        public string PrincipalId { get; internal set; }
    }
}
