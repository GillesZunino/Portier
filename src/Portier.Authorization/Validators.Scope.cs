// -----------------------------------------------------------------------------------
// Copyright 2017, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;

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
                throw new ArgumentOutOfRangeException(nameof(scope), Resources.GetString("Validators_ScopeMustNotBeNullOrEmpty"));
            }

            // Scope must be rooted (start with one of the component delimiter we know)
            // PERFORMANCE: We do not use LINQ or foreach here as they allocate memory
            bool found = false;
            for (int index = 0; index < ScopePrefixMatcher.ScopeComponentDelimiters.Count; index++)
            {
                if (scope[0] == ScopePrefixMatcher.ScopeComponentDelimiters[index])
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                throw new ArgumentOutOfRangeException(nameof(scope), string.Format(CultureInfo.CurrentCulture, Resources.GetString("Validators_ScopeMustStartWithDelimiter"), scope, string.Join(", ", ScopePrefixMatcher.ScopeComponentDelimiters)));
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
                throw new ArgumentNullException(nameof(scopes), Resources.GetString("Validators_CollectionOfScopesCannotBeNull"));
            }

            bool hasParents = false;

            foreach (string parent in scopes)
            {
                Validators.ValidateScope(parent);
                hasParents = true;
            }

            if (!hasParents)
            {
                throw new ArgumentOutOfRangeException(nameof(scopes), Resources.GetString("Validators_CollectionOfScopesMustContainOneEntry"));
            }
        }

        /// <summary>
        /// Validates a collection of scopes. Errors are reported via exceptions.
        /// </summary>
        /// <param name="scopes">One or more parent scopes.</param>
        public static void ValidateScopes(IReadOnlyList<string> scopes)
        {
            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes), Resources.GetString("Validators_CollectionOfScopesCannotBeNull"));
            }

            bool hasParents = false;

            // PERFORMANCE: We do not use LINQ (parents.Any(...)) as it allocates memory
            // PERFORMANCE: We do not use foreach (string parent in parents) because it allocates memory
            for (int index = 0; index < scopes.Count; index++)
            {
                Validators.ValidateScope(scopes[index]);
                hasParents = true;
            }

            if (!hasParents)
            {
                throw new ArgumentOutOfRangeException(nameof(scopes), Resources.GetString("Validators_CollectionOfScopesMustContainOneEntry"));
            }
        }
    }
}
