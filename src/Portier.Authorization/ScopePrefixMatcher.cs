// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Portier.Authorization
{
    /// <summary>
    /// Checks wether an RBAC scope matches an RBAC parent.
    /// </summary>
    public static class ScopePrefixMatcher
    {
        private static readonly char[] scopeComponentDelimiters = new char[] { '/' };
        /// <summary>
        /// Collection of valid component delimiters.
        /// </summary>
        public static readonly ReadOnlyCollection<char> ScopeComponentDelimiters = new ReadOnlyCollection<char>(scopeComponentDelimiters);

        /// <summary>
        /// Checks if the given child scope matches the parent scope.
        /// </summary>
        /// <param name="parent">Parent scope.</param>
        /// <param name="child">Child scope.</param>
        /// <returns>true if the child scope matches the parent; otherwise, false.</returns>
        /// <remarks>All scopes must start with a valid scope delimiter (aka be rooted) or <see cref="ArgumentOutOfRangeException"/> is thrown.</remarks>
        public static bool IsPrefixMatch(string parent, string child)
        {
            Validators.ValidateScope(parent);
            Validators.ValidateScope(child);

            return ScopeComponentsPrefixMatchChild(GetScopeComponents(parent), GetScopeComponents(child));
        }

        /// <summary>
        /// Checks if the given child scope matches any of the parents.
        /// </summary>
        /// <param name="parents">One or more parent scopes.</param>
        /// <param name="child">Child scope.</param>
        /// <returns>true if the child scope matches at least one parent; otherwise, false.</returns>
        /// <remarks>All scopes must start with a valid scope delimiter (aka be rooted) or <see cref="ArgumentOutOfRangeException"/> is thrown.</remarks>
        public static bool IsPrefixMatch(IEnumerable<string> parents, string child)
        {
            Validators.ValidateScopes(parents);
            Validators.ValidateScope(child);

            string[] childComponents = GetScopeComponents(child);

            // PERFORMANCE: We do not use LINQ (parents.Any(...)) as it allocates memory
            foreach (string parent in parents)
            {
                if (ScopeComponentsPrefixMatchChild(GetScopeComponents(parent), childComponents))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ScopeComponentsPrefixMatchChild(string[] scopeComponents, string[] childComponents)
        {
            // Convention: any empty scope (aka [] or "/" or "/////" matches any child
            if (scopeComponents.Length > 0)
            {
                if (childComponents.Length >= scopeComponents.Length)
                {
                    for (int index = 0; index < scopeComponents.Length; ++index)
                    {
                        if (string.Compare(scopeComponents[index], childComponents[index], StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            return false;
                        }
                    }

                    return true;
                }

                return false;
            }

            return true;
        }

        private static string[] GetScopeComponents(string scope)
        {
            return scope.Split(scopeComponentDelimiters, StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
