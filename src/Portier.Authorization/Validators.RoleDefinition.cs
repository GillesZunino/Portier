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
                throw new ArgumentOutOfRangeException(nameof(id), Resources.GetString("Validators_RoleDefinitionIdMustNotBeNullOrEmpty"));
            }

            ValidatePermissions(permissions);
            Validators.ValidateScopes(assignableScopes);
        }

        private static void ValidatePermissions(IEnumerable<string> permissions)
        {
            if (permissions == null)
            {
                throw new ArgumentOutOfRangeException(nameof(permissions), Resources.GetString("Validators_RoleDefinitionPermissionsMustNotBeNull"));
            }

            // There must be at least one permission - All permissions must be valid
            bool hasEntries = false;
            foreach (string permission in permissions)
            {
                hasEntries = true;

                Validators.ValidatePermissionPattern(permission);
            }

            if (!hasEntries)
            {
                throw new ArgumentOutOfRangeException(nameof(permissions), Resources.GetString("Validators_RoleDefinitionAssignableScopesMustContainOneEntry"));
            }
        }
    }
}
