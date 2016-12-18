// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Security.Claims;

namespace Portier.Authorization
{
    /// <summary>
    /// Defines the authorization engine.
    /// </summary>
    public interface IAuthorizationEngine
    {
        /// <summary>
        /// Check if a user is authorized to perform an action on a resource
        /// </summary>
        /// <param name="claimsIdentity">Idenitity of the user to perform authorization checks for.</param>
        /// <param name="resource">Resource the user is trying to access.</param>
        /// <param name="action">Action the suer wishes to perform.</param>
        /// <returns>Result of authorization check in the form of a <see cref="AuthorizationDecision"/></returns>
        AuthorizationDecision CheckAccess(ClaimsIdentity claimsIdentity, string resource, string action);
    }
}