// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;

namespace Portier.Authorization
{
    /// <summary>
    /// Validation primitives for IRoleDefinition objects.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Validates an IRoleDefinition.
        /// </summary>
        /// <param name="roleDefinition">Role definition instance to validate.</param>
        public static void ValidateRoleDefinition(IRoleDefinition roleDefinition)
        {
            if (roleDefinition == null)
            {
                throw new ArgumentNullException(nameof(roleDefinition));
            }

            ValidateRoleDefinitionComponents(roleDefinition.Id, roleDefinition.AssignableScopes, roleDefinition.Permissions);
        }

        /// <summary>
        /// Validates components of an IRoleDefinition.
        /// </summary>
        /// <param name="id">Role definition id.</param>
        /// <param name="permissions">Permissions granted by role definition.</param>
        /// <param name="assignableScopes">Scopes at which the role definition can be.</param>
        public static void ValidateRoleDefinitionComponents(string id, IEnumerable<string> assignableScopes, IEnumerable<string> permissions)
        {
            if (string.IsNullOrEmpty(id))
            {
                throw new ArgumentOutOfRangeException(nameof(id), "Role Definition 'Id' cannot be null or empty");
            }

            ValidatePermissions(permissions);
            ValidateAssignableScopes(assignableScopes);
        }

        private static void ValidateAssignableScopes(IEnumerable<string> assignableScopes)
        {
            if (assignableScopes == null)
            {
                throw new ArgumentOutOfRangeException(nameof(assignableScopes), "Role Definition 'AssignableScopes' cannot be null");
            }

            // There must be at least one scope - All scopes must be valid
            bool hasEntries = false;
            foreach (string scope in assignableScopes)
            {
                hasEntries = true;

                ScopePrefixMatcher.ValidateScope(scope, nameof(assignableScopes));
            }

            if (!hasEntries)
            {
                throw new ArgumentOutOfRangeException(nameof(assignableScopes), "Role Definition 'AssignableScopes' must contain at least one entry");
            }
        }

        private static void ValidatePermissions(IEnumerable<string> permissions)
        {
            if (permissions == null)
            {
                throw new ArgumentOutOfRangeException(nameof(permissions), "Role Definition 'Permissions' cannot be null");
            }

            // There must be at least one permission - All permissions must be valid
            bool hasEntries = false;
            foreach (string permission in permissions)
            {
                hasEntries = true;

                PermissionPatternMatcher.ValidatePermissionPattern(permission, nameof(permissions));
            }

            if (!hasEntries)
            {
                throw new ArgumentOutOfRangeException(nameof(permissions), "Role Definition 'AssignableScopes' must contain at least one entry");
            }
        }
    }
}
