// -----------------------------------------------------------------------------------
// Copyright 2017, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Linq;

namespace Portier.Authorization
{
    /// <summary>
    /// Validation primitives for permission strings.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Validates a permission. Errors are reported via exceptions.
        /// </summary>
        /// <param name="permission">Permission to validate.</param>
        public static void ValidatePermission(string permission)
        {
            if (string.IsNullOrEmpty(permission))
            {
                throw new ArgumentOutOfRangeException(nameof(permission), Resources.GetString("Validators_PermissionMustNotBeNullOrEmpty"));
            }

            // Permission must not contain wildcards
            if (permission.Contains(PermissionPatternMatcher.Wildcard))
            {
                throw new ArgumentOutOfRangeException(nameof(permission), string.Format(CultureInfo.CurrentCulture, Resources.GetString("Validators_PermissionCannotContainWildcards"), permission));
            }

            // Permission must not start with one of the component delimiter we know
            if (PermissionPatternMatcher.PermissionDelimiters.Any((c) => c == permission[0]))
            {
                throw new ArgumentOutOfRangeException(nameof(permission), string.Format(CultureInfo.CurrentCulture, Resources.GetString("Validators_PermissionMustNotStartWithDelimiter"), permission, string.Join(", ", PermissionPatternMatcher.PermissionDelimiters)));
            }
        }

        /// <summary>
        /// Validates a permission pattern. Errors are reported via exceptions.
        /// </summary>
        /// <param name="pattern">Permission pattern to validate.</param>
        public static void ValidatePermissionPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                throw new ArgumentOutOfRangeException(nameof(pattern), Resources.GetString("Validators_PermissionPatternMustNotBeNullOrEmpty"));
            }

            // Pattern must not start with one of the component delimiter we know
            if (PermissionPatternMatcher.PermissionDelimiters.Any((c) => c == pattern[0]))
            {
                throw new ArgumentOutOfRangeException(nameof(pattern), string.Format(CultureInfo.CurrentCulture, Resources.GetString("Validators_PermissionPatternMustNotStartWithDelimiter"), pattern, string.Join(", ", PermissionPatternMatcher.PermissionDelimiters)));
            }
        }
    }
}
