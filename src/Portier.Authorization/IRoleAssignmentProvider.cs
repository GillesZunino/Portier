// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Claims;

namespace Portier.Authorization
{
    /// <summary>
    /// Defines a provider capable of retrieving role assignments.
    /// </summary>
    public interface IRoleAssignmentProvider
    {
        /// <summary>
        /// Gets a list of role assignment for a given user.
        /// </summary>
        /// <param name="claimsIdentity">User to retrieve role assignments for, represented as a <see cref="ClaimsIdentity"/>.</param>
        /// <returns>Collection of role assignments for this user.</returns>
        IEnumerable<IRoleAssignment> GetRoleAssignmentsByClaimsIdentity(ClaimsIdentity claimsIdentity);
    }
}