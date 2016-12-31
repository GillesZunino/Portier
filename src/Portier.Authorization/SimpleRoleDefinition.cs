// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Collections.Generic;

namespace Portier.Authorization
{
    /// <summary>
    /// A simple role definition.
    /// </summary>
    public class SimpleRoleDefinition : IRoleDefinition
    {
        /// <summary>
        /// Gets or sets the globally unique identifier of the role definition.
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets or sets the role assignment display name.
        /// </summary>
        public string DisplayName { get; private set; }

        /// <summary>
        /// Gets or sets the list of scopes this role definition can be assigned at.
        /// </summary>
        public IEnumerable<string> AssignableScopes { get; private set; }

        /// <summary>
        /// Gets or sets the list of permissions this role definition grants.
        /// </summary>
        public IEnumerable<string> Permissions { get; private set; }

        /// <summary>
        /// Creates a new instance of SimpleRoleDefinition.
        /// </summary>
        /// <param name="id">Globally unique identifier.</param>
        /// <param name="displayName">Display name.</param>
        /// <param name="assignableScopes">List of scopes this role definition can be assigned at.</param>
        /// <param name="permissions">List of permissions this role definition grants.</param>
        public SimpleRoleDefinition(string id, string displayName, IEnumerable<string> assignableScopes, IEnumerable<string> permissions)
        {
            Validators.ValidateRoleDefinitionComponents(id, assignableScopes, permissions);
          
            Id = id;
            DisplayName = displayName;
            AssignableScopes = assignableScopes;
            Permissions = permissions;
        }
    }
}
