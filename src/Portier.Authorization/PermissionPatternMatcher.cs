// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.ObjectModel;

namespace Portier.Authorization
{
    /// <summary>
    /// Checks wether an RBAC permission matches an RBAC permission pattern.
    /// </summary>
    public static class PermissionPatternMatcher
    {
        private static readonly char[] permissionDelimiters = new char[] { '/' };

        /// <summary>
        /// Permission wildcard character.
        /// </summary>
        public const string Wildcard = "*";

        /// <summary>
        /// Collection of valid permission delimiters.
        /// </summary>
        public static readonly ReadOnlyCollection<char> PermissionDelimiters = new ReadOnlyCollection<char>(permissionDelimiters);

        /// <summary>
        /// Determines wether an RBAC permission matches an RBAC pattern.
        /// </summary>
        /// <param name="pattern">RBAC pattern.</param>
        /// <param name="permission">RBAC permission to check against the pattern.</param>
        /// <returns>true if the specified permission matches the pattern; otherwise, false.</returns>
        public static bool IsMatch(string pattern, string permission)
        {
            Validators.ValidatePermissionPattern(pattern);
            Validators.ValidatePermission(permission);

            // Split both the permission pattern (Microsoft.Compute/virtualMachine/*/read) and the permission (Microsoft.Compute/virtualMachine/myLittleVm/read) on the delimiter ("/")
            string[] patternComponents = pattern.Split(permissionDelimiters, StringSplitOptions.RemoveEmptyEntries);
            string[] permissionComponents = permission.Split(permissionDelimiters, StringSplitOptions.RemoveEmptyEntries);

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
    }
}
