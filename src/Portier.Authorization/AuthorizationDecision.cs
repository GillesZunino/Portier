// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Portier.Authorization
{
    /// <summary>
    /// Represents the decision of a single authorization request.
    /// </summary>
    public class AuthorizationDecision
    {
        /// <summary>
        /// Gets wether the request was authorized.
        /// </summary>
        public bool IsAccessGranted { get; private set; }

        /// <summary>
        /// If authorization is granted, gets role assignment(s) <see cref="IRoleAssignment"/> which led to authorization.
        /// </summary>
        public ReadOnlyCollection<IRoleAssignment> SelectedRoleAssignments { get; private set; }

        /// <summary>
        /// Creates a new instance of AuthorizationDecision.
        /// </summary>
        internal AuthorizationDecision(bool accessGranted, IList<IRoleAssignment> selectedRoleAssignments)
        {
            IsAccessGranted = accessGranted;
            SelectedRoleAssignments = new ReadOnlyCollection<IRoleAssignment>(selectedRoleAssignments);
        }
    }
}