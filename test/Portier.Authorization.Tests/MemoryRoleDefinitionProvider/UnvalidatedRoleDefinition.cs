// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Collections.Generic;

namespace Portier.Authorization.Tests
{
    /// <summary>
    /// A implementation of IRoleDefinition with no validation for the purpose of testing.
    /// </summary>
    internal class UnvalidatedRoleDefinition : IRoleDefinition
    {
        public string Id { get; set; }

        public string DisplayName { get; set; }

        public IEnumerable<string> AssignableScopes { get; set; }

        public IEnumerable<string> Permissions { get; set; }

        public UnvalidatedRoleDefinition(string id, string displayName, IEnumerable<string> assignableScopes, IEnumerable<string> permissions)
        {
            Id = id;
            DisplayName = displayName;
            AssignableScopes = assignableScopes;
            Permissions = permissions;
        }
    }
}
