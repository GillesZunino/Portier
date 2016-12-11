// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Security.Claims;

namespace Portier.Authorization
{
    public interface IAuthorization
    {
        bool CheckAccess(ClaimsPrincipal claimsPrincipal, string resource, string permission);
    }
}