// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Portier.Authorization
{
    /// <summary>
    /// Authorization engine.
    /// </summary>
    public class AuthorizationEngine : IAuthorizationEngine
    {
        private static readonly AuthorizationCheckCallback DefaultAuthorizationCheckCallback = (claimsIdentity, roleAssignment, roleDefinition) => true;
        private static readonly AuthorizationDecision AccessDeniedAuthorizationDecision = new AuthorizationDecision(false, new List<IRoleAssignment>());

        /// <summary>
        /// Gets the role assignment provider currently in use by the authorization engine.
        /// </summary>
        public IRoleAssignmentProvider RoleAssignmentProvider { get; private set; }

        /// <summary>
        /// Gets the role defiunition provider currently in use by the authorization engine.
        /// </summary>
        public IRoleDefinitionProvider RoleDefinitionProvider { get; private set; }

        /// <summary>
        /// Creates a new authorization engine instance.
        /// </summary>
        /// <param name="roleAssignmentProvider">Instance of role assignment provider <see cref="IRoleAssignmentProvider"/>.</param>
        /// <param name="roleDefinitionProvider">Instance of role definition provider <see cref="IRoleDefinitionProvider"/>.</param>
        public AuthorizationEngine(IRoleAssignmentProvider roleAssignmentProvider, IRoleDefinitionProvider roleDefinitionProvider)
        {
            if (roleAssignmentProvider == null)
            {
                throw new ArgumentNullException(nameof(roleAssignmentProvider));
            }

            if (roleDefinitionProvider == null)
            {
                throw new ArgumentNullException(nameof(roleDefinitionProvider));
            }

            RoleAssignmentProvider = roleAssignmentProvider;
            RoleDefinitionProvider = roleDefinitionProvider;
        }

        /// <summary>
        /// Check if a user is authorized to perform an action on a resource
        /// </summary>
        /// <param name="claimsIdentity">Identity of the user to perform authorization checks for.</param>
        /// <param name="resource">Resource the user is trying to access.</param>
        /// <param name="permission">Permission to check for authorization.</param>
        /// <returns>Result of authorization check in the form of a <see cref="AuthorizationDecision"/>.</returns>
        public AuthorizationDecision CheckAccess(ClaimsIdentity claimsIdentity, string resource, string permission)
        {
            return CheckAccess(claimsIdentity, resource, permission, DefaultAuthorizationCheckCallback);
        }

        /// <summary>
        /// Check if a user is authorized to perform an action on a resource
        /// </summary>
        /// <param name="claimsIdentity">Identity of the user to perform authorization checks for.</param>
        /// <param name="resource">Resource the user is trying to access.</param>
        /// <param name="permission">Permission to check for authorization.</param>
        /// <param name="authorizationCheck">Callback to perform additional checks after authorization has been granted.</param>
        /// <returns>Result of authorization check in the form of a <see cref="AuthorizationDecision"/>.</returns>
        public AuthorizationDecision CheckAccess(ClaimsIdentity claimsIdentity, string resource, string permission, AuthorizationCheckCallback authorizationCheck)
        {
            return CheckAccess(claimsIdentity, resource, permission, authorizationCheck, true);
        }

        /// <summary>
        /// Check if a user is authorized to perform an action on a resource
        /// </summary>
        /// <param name="claimsIdentity">Identity of the user to perform authorization checks for.</param>
        /// <param name="resource">Resource the user is trying to access.</param>
        /// <param name="permission">Permission to check for authorization.</param>
        /// <param name="authorizationCheck">Callback to perform additional checks after authorization has been granted.</param>
        /// <param name="evaluateAllRoleAssignments">true to evaluate all role assignments even if authorization is granted, false to stop at the first match found.</param>
        /// <returns>Result of authorization check in the form of a <see cref="AuthorizationDecision"/>.</returns>
        public AuthorizationDecision CheckAccess(ClaimsIdentity claimsIdentity, string resource, string permission, AuthorizationCheckCallback authorizationCheck, bool evaluateAllRoleAssignments)
        {
            if (claimsIdentity == null)
            {
                throw new ArgumentNullException(nameof(claimsIdentity));
            }

            ScopePrefixMatcher.ValidateScope(resource, nameof(resource));
            PermissionPatternMatcher.ValidatePermission(permission, nameof(permission));

            if (authorizationCheck == null)
            {
                throw new ArgumentNullException(nameof(authorizationCheck));
            }

            return CheckAccessInternal(claimsIdentity, resource, permission, authorizationCheck, !evaluateAllRoleAssignments);
        }

        private AuthorizationDecision CheckAccessInternal(ClaimsIdentity claimsIdentity, string resource, string permission, AuthorizationCheckCallback authorizationCheck, bool stopOnPermissionGranted)
        {
            List<IRoleAssignment> authorizedRoleAssignments = null;

            // Get all role assignments 
            IEnumerable<IRoleAssignment> roleAssignmentsForUser = RoleAssignmentProvider.GetRoleAssignmentsByClaimsIdentity(claimsIdentity);
            if (roleAssignmentsForUser != null)
            {
                // Get all role assignments where the resource is in scope
                IEnumerable<IRoleAssignment> roleAssignmentsAtScope = roleAssignmentsForUser.Where<IRoleAssignment>(roleAssignment => ScopePrefixMatcher.IsPrefixMatch(roleAssignment.Scope, resource));
                if (roleAssignmentsAtScope != null)
                {
                    // Search role assignments for one that grants the requested permission
                    foreach (IRoleAssignment roleAssignment in roleAssignmentsAtScope)
                    {
                        // Acquire the rolde definition for the role assignment
                        IRoleDefinition roleDefinition = RoleDefinitionProvider.GetRoleDefinitionById(roleAssignment.RoleDefinitionId);
                        if (roleDefinition != null)
                        {
                            // Can the role definition be assigned at the resource scope ?
                            if (ScopePrefixMatcher.IsPrefixMatch(roleDefinition.AssignableScopes, roleAssignment.Scope))
                            {
                                // Does the role definition grant access to this permission?
                                if (roleDefinition.Permissions.Any((pattern) => PermissionPatternMatcher.IsMatch(pattern, permission)))
                                {
                                    // Perform a final check now that we have a possible authorization granted
                                    if (authorizationCheck(claimsIdentity, roleAssignment, roleDefinition))
                                    {
                                        // User is allowed to perform this action - We only allocate the list of matching role assignments only the permission is granted
                                        if (authorizedRoleAssignments == null)
                                        {
                                            authorizedRoleAssignments = new List<IRoleAssignment>();
                                        }
                                        authorizedRoleAssignments.Add(roleAssignment);

                                        // Stop on first match if we have been asked to
                                        if (stopOnPermissionGranted)
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Format result of the authorization check
            return authorizedRoleAssignments != null ? new AuthorizationDecision(true, authorizedRoleAssignments) : AccessDeniedAuthorizationDecision; 
        }
    }
}
