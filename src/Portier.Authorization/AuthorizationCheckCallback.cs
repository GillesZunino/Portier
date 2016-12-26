// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Security.Claims;

namespace Portier.Authorization
{
    /// <summary>
    /// Performs optional checks once authorization has been granted.
    /// </summary>
    /// <param name="claimsIdentity">Identity of the user to perform authorization checks for.</param>
    /// <param name="roleAssignment">Role assignment providing authorization.</param>
    /// <param name="roleDefinition">Role definition matching the role assignment.</param>
    /// <returns>true if the given Identity is authorized; false otherwise.</returns>
    /// <remarks>This callkback is meant to perform additional checks. It is called only when the role assignment grants users authorization.</remarks>
    public delegate bool AuthorizationCheckCallback(ClaimsIdentity claimsIdentity, IRoleAssignment roleAssignment, IRoleDefinition roleDefinition);
}
