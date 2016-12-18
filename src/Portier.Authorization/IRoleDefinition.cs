// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Collections.Generic;

namespace Portier.Authorization
{
    /// <summary>
    /// Defines a role definition.
    /// </summary>
    public interface IRoleDefinition
    {
        /// <summary>
        /// Gets the globally unique identifier of the role definition.
        /// </summary>
        string Id { get; }

        /// <summary>
        /// Gets the list of permissions this role definition grants.
        /// </summary>
        IEnumerable<string> Permissions { get; }
        
        /// <summary>
        /// Gets the list of scopes this role definition can be assigned at.
        /// </summary>
        IEnumerable<string> AssignableScopes { get; }
    }
}
