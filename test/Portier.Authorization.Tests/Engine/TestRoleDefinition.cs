// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Collections.Generic;

namespace Portier.Authorization.Tests.Engine
{
    /// <summary>
    /// A generic Role Definition for testing.
    /// </summary>
    internal class TestRoleDefinition : IRoleDefinition
    {
        public string Id { get; internal set; }

        public string DisplayName { get; internal set; }

        public IEnumerable<string> AssignableScopes { get; internal set; }

        public IEnumerable<string> Permissions { get; internal set; }
    }
}
