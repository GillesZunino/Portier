// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Portier.Authorization
{
    /// <summary>
    /// Checks wether an RBAC scope matches an RBAC parent.
    /// </summary>
    public static class ScopePrefixMatcher
    {
        private static readonly char[] ScopeComponentDelimiters = new char[] { '/' };

        /// <summary>
        /// Checks if the given child scope matches the parent scope.
        /// </summary>
        /// <param name="parent">Parent scope.</param>
        /// <param name="child">Child scope.</param>
        /// <returns>true if the child scope matches the parent; otherwise, false.</returns>
        /// <remarks>All scopes must start with a valid scope delimiter (aka be rooted) or <see cref="ArgumentOutOfRangeException"/> is thrown.</remarks>
        public static bool IsPrefixMatch(string parent, string child)
        {
            ValidateScope(parent, nameof(parent));
            ValidateScope(child, nameof(child));

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
            ValidateParentScopes(parents, nameof(parents));
            ValidateScope(child, nameof(child));

            string[] childComponents = GetScopeComponents(child);
            return parents.Any(parent => ScopeComponentsPrefixMatchChild(GetScopeComponents(parent), childComponents));
        }

        /// <summary>
        /// Validates a scope. Errors are reported via exceptions.
        /// </summary>
        /// <param name="scope">Scope to validate.</param>
        /// <param name="argumentName">Name of argument in case of failure.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ValidateScope(string scope, string argumentName)
        {
            // Scope must not  be null or empty
            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentOutOfRangeException(argumentName, "Scope must not be null or empty");
            }

            // Scope must be rooted (start with one of the component delimiter we know)
            if (ScopeComponentDelimiters.Any((c) => c != scope[0]))
            {
                throw new ArgumentOutOfRangeException(argumentName, string.Format(CultureInfo.CurrentCulture, "Scope '{0}' must start with a delimiter (one of '{1}')", scope, string.Join(", ", ScopeComponentDelimiters)));
            }
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
            return scope.Split(ScopeComponentDelimiters, StringSplitOptions.RemoveEmptyEntries);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ValidateParentScopes(IEnumerable<string> parents, string argumentName)
        {
            if (parents == null)
            {
                throw new ArgumentNullException(argumentName);
            }

            bool hasParents = false;

            foreach (string parent in parents)
            {
                ValidateScope(parent, argumentName);
                hasParents = true;
            }

            if (!hasParents)
            {
                throw new ArgumentOutOfRangeException(argumentName, "At least one parent scope must be provided");
            }
        }
    }
}
