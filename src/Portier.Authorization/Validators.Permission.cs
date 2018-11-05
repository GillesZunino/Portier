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
            // PERFORMANCE: We do not use LINQ or foreach here as they allocate memory
            bool found = false;
            for (int index = 0; index < PermissionPatternMatcher.PermissionDelimiters.Count; index++)
            {
                if (permission[0] == PermissionPatternMatcher.PermissionDelimiters[index])
                {
                    found = true;
                    break;
                }
            }

            if (found)
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
            // PERFORMANCE: We do not use LINQ or foreach here as they allocate memory
            bool found = false;
            for (int index = 0; index < PermissionPatternMatcher.PermissionDelimiters.Count; index++)
            {
                if (pattern[0] == PermissionPatternMatcher.PermissionDelimiters[index])
                {
                    found = true;
                    break;
                }
            }

            if (found)
            {
                throw new ArgumentOutOfRangeException(nameof(pattern), string.Format(CultureInfo.CurrentCulture, Resources.GetString("Validators_PermissionPatternMustNotStartWithDelimiter"), pattern, string.Join(", ", PermissionPatternMatcher.PermissionDelimiters)));
            }
        }
    }
}
