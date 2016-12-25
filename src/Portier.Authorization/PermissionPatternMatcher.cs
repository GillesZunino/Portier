// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Portier.Authorization
{
    /// <summary>
    /// Checks wether an RBAC permission matches an RBAC permission pattern.
    /// </summary>
    public static class PermissionPatternMatcher
    {
        private const string Wildcard = "*";
        private static readonly char[] PermissionDelimiters = new char[] { '/' };

        /// <summary>
        /// Determines wether an RBAC permission matches an RBAC pattern.
        /// </summary>
        /// <param name="pattern">RBAC pattern.</param>
        /// <param name="permission">RBAC permission to check against the pattern.</param>
        /// <returns>true if the specified permission matches the pattern; otherwise, false.</returns>
        public static bool IsMatch(string pattern, string permission)
        {
            EnsureValidPermissionPattern(pattern, nameof(pattern));
            EnsureValidPermission(permission, nameof(permission));

            // Split both the permission pattern (Microsoft.Compute/virtualMachine/*/read) and the permission (Microsoft.Compute/virtualMachine/myLittleVm/read) on the delimiter ("/")
            string[] patternComponents = pattern.Split(PermissionDelimiters, StringSplitOptions.RemoveEmptyEntries);
            string[] permissionComponents = permission.Split(PermissionDelimiters, StringSplitOptions.RemoveEmptyEntries);

            int patternSegmentIndex = 0;
            int permissionSegmentIndex = 0;

            int patternRestartPointIndex = -1;

            while (true)
            {
                // Traverse permission components one by one trying to match them to the corresponding pattern components
                while (permissionSegmentIndex < permissionComponents.Length)
                {
                    // Permission component matches pattern component exactly ? (aka in the example above "Microsoft.Compute" and "Microsoft.Compute" or "read" and "read")
                    if ((patternSegmentIndex < patternComponents.Length) && (string.Compare(patternComponents[patternSegmentIndex], permissionComponents[permissionSegmentIndex], StringComparison.OrdinalIgnoreCase) == 0))
                    {
                        // Move to next permission and pattern components
                        patternSegmentIndex++;
                        permissionSegmentIndex++;
                    }
                    else
                    {
                        // Is the pattern component a wildcard ? (aka similar to "Microsoft.Compute/*" or "Microsoft.Compute/*/virtualMachines/*/action")
                        if ((patternSegmentIndex < patternComponents.Length) && (string.CompareOrdinal(Wildcard, patternComponents[patternSegmentIndex]) == 0))
                        {
                            patternSegmentIndex++;

                            // We have encountered a wildcard - The next segment becomes a possible restart point in the pattern
                            //
                            // Consider the following situation for which we would like the permission to match the pattern:
                            //
                            //   pattern    : A/*/B/C/D
                            //   permission : A/s/B/C/XXX/B/C/D
                            //                ^       ^
                            //  There are two possible starts for pattern /B/C/D marked with ^ above
                            //  The first one is a false start (/B/C/XXX). The second one ends up being a match (/B/C/D)
                            //
                            patternRestartPointIndex = patternSegmentIndex;
                        }
                        else
                        {
                            // Is it possible to restart earlier in the pattern ?
                            if (patternRestartPointIndex != -1)
                            {
                                // Restart pattern scanning at the last known restart position
                                patternSegmentIndex = patternRestartPointIndex;

                                // Did we consume the pattern entirely ?
                                if (patternSegmentIndex < patternComponents.Length)
                                {
                                    // Move to the next pattern segment if the pattern at the restart point matches the permission segment
                                    if (string.Compare(patternComponents[patternSegmentIndex], permissionComponents[permissionSegmentIndex], StringComparison.OrdinalIgnoreCase) == 0)
                                    {
                                        patternSegmentIndex++;
                                    }

                                    // Move to the next segment in the permission
                                    permissionSegmentIndex++;
                                }
                                else
                                {
                                    // Pattern consumed entirely - Permission matches the pattern
                                    return true;
                                }
                            }
                            else
                            {
                                // No restart is possible - Permission does not match pattern
                                return false;
                            }
                        }
                    }
                }

                // Did we consume the pattern entirely ?
                if (patternSegmentIndex < patternComponents.Length)
                {
                    // Pattern has not yet been scanned entirely yet we consumed the entire permission - For a match, the next segment of the pattern must be one or more wildcards
                    if (StringComparer.Ordinal.Equals(Wildcard, patternComponents[patternSegmentIndex]))
                    {
                        patternSegmentIndex++;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    // The pattern has been entirely scanned - We have found a match
                    return true;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EnsureValidPermissionPattern(string pattern, string argumentName)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                throw new ArgumentOutOfRangeException(argumentName, "Permission pattern must not be null or empty");
            }

            // Pattern must not start with one of the component delimiter we know
            if (PermissionDelimiters.Any((c) => c == pattern[0]))
            {
                throw new ArgumentOutOfRangeException(argumentName, string.Format(CultureInfo.CurrentCulture, "Permission pattern '{0}' must not start with a delimiter (one of '{1}')", pattern, string.Join(", ", PermissionDelimiters)));
            }
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EnsureValidPermission(string permission, string argumentName)
        {
            if (string.IsNullOrEmpty(permission))
            {
                throw new ArgumentOutOfRangeException(argumentName, "Permission must not be null or empty");
            }

            // Permission must not contain wildcards
            if (permission.Contains(Wildcard))
            {
                throw new ArgumentOutOfRangeException(argumentName, string.Format(CultureInfo.CurrentCulture, "Permission cannot contain wildcards - '{0}'", permission));
            }

            // Permission must not start with one of the component delimiter we know
            if (PermissionDelimiters.Any((c) => c == permission[0]))
            {
                throw new ArgumentOutOfRangeException(argumentName, string.Format(CultureInfo.CurrentCulture, "Permission '{0}' must not start with a delimiter (one of '{1}')", permission, string.Join(", ", PermissionDelimiters)));
            }
        }
    }
}
