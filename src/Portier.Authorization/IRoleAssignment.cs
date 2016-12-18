// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Security.Claims;

namespace Portier.Authorization
{
    /// <summary>
    /// Defines a role assignment.
    /// </summary>
    public interface IRoleAssignment
    {
        /// <summary>
        /// Gets the role assigment globally unique identifier.
        /// </summary>
        string Id { get; }

        /// <summary>
        /// Gets the role definition globally unique identifier for this role assignment.
        /// </summary>
        string RoleDefinitionId { get; }

        /// <summary>
        /// Gets the scope the role is assigned at.
        /// </summary>
        string Scope { get; }

        /// <summary>
        /// Determines wether the role assignment is made for the given identity.
        /// </summary>
        /// <param name="claimsIdentity"></param>
        /// <returns>true if the role is assigned to the given identity, false otherwise.</returns>
        bool AppliesToPrincipal(ClaimsIdentity claimsIdentity);
    }
}