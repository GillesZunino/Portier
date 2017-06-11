// -----------------------------------------------------------------------------------
// Copyright 2017, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Portier.Authorization
{
    /// <summary>
    /// Validation primitives for Scope strings.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Validates a scope. Errors are reported via exceptions.
        /// </summary>
        /// <param name="scope">Scope to validate.</param>
        public static void ValidateScope(string scope)
        {
            // Scope must not  be null or empty
            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentOutOfRangeException(nameof(scope), "Scope must not be null or empty");
            }

            // Scope must be rooted (start with one of the component delimiter we know)
            if (ScopePrefixMatcher.ScopeComponentDelimiters.Any((c) => c != scope[0]))
            {
                throw new ArgumentOutOfRangeException(nameof(scope), string.Format(CultureInfo.CurrentCulture, "Scope '{0}' must start with a delimiter (one of '{1}')", scope, string.Join(", ", ScopePrefixMatcher.ScopeComponentDelimiters)));
            }
        }

        /// <summary>
        /// Validates a collection of scopes. Errors are reported via exceptions.
        /// </summary>
        /// <param name="scopes">One or more parent scopes.</param>
        public static void ValidateScopes(IEnumerable<string> scopes)
        {
            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes), "Collection of scopes cannot be null");
            }

            bool hasParents = false;

            foreach (string parent in scopes)
            {
                Validators.ValidateScope(parent);
                hasParents = true;
            }

            if (!hasParents)
            {
                throw new ArgumentOutOfRangeException(nameof(scopes), "At least one scope must be provided");
            }
        }
    }
}
