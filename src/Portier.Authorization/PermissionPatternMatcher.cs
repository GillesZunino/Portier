// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;

namespace Portier.Authorization
{
    /// <summary>
    /// Checks wether an RBAC action matches an RBAC pattern.
    /// </summary>
    public static class PermissionPatternMatcher
    {
        private const string Wildcard = "*";
        private static readonly char[] ActionDelimiters = new char[] { '/' };

        /// <summary>
        /// Determines wether an RBAC action matches an RBAC pattern.
        /// </summary>
        /// <param name="pattern">RBAC pattern.</param>
        /// <param name="action">RBAC action to check against the pattern.</param>
        /// <returns>true if the specified objects are equal; otherwise, false.</returns>
        public static bool IsMatch(string pattern, string action)
        {
            // Make null or emtpy pattern / action never match - We do not want a null or empty string to ever be understood as "authorization granted"
            if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(action))
            {
                return false;
            }

            // Split both the action pattern (Microsoft.Compute/virtualMachine/*/read) and the action (Microsoft.Compute/virtualMachine/myLittleVm/read) on the delimiter ("/")
            string[] patternComponents = pattern.Split(ActionDelimiters, StringSplitOptions.RemoveEmptyEntries);
            string[] actionComponents = action.Split(ActionDelimiters, StringSplitOptions.RemoveEmptyEntries);

            int patternSegmentIndex = 0;
            int actionSegmentIndex = 0;

            int patternRestartPointIndex = -1;

            while (true)
            {
                // Traverse action components one by one trying to match them to the corresponding pattern components
                while (actionSegmentIndex < actionComponents.Length)
                {
                    // Action component matches pattern component exactly ? (aka in the example above "Microsoft.Compute" and "Microsoft.Compute" or "read" and "read")
                    if ((patternSegmentIndex < patternComponents.Length) && (string.Compare(patternComponents[patternSegmentIndex], actionComponents[actionSegmentIndex], StringComparison.OrdinalIgnoreCase) == 0))
                    {
                        // Move to next action and pattern components
                        patternSegmentIndex++;
                        actionSegmentIndex++;
                    }
                    else
                    {
                        // Is the pattern component a wildcard ? (aka similar to "Microsoft.Compute/*" or "Microsoft.Compute/*/virtualMachines/*/action")
                        if ((patternSegmentIndex < patternComponents.Length) && (string.CompareOrdinal(Wildcard, patternComponents[patternSegmentIndex]) == 0))
                        {
                            patternSegmentIndex++;

                            // We have encountered a wildcard - The next segment becomes a possible restart point in the pattern
                            //
                            // Consider the following situation for which we would like the action to match the pattern:
                            //
                            //   pattern: A/*/B/C/D
                            //   action : A/s/B/C/XXX/B/C/D
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
                                    // Move to the next pattern segment if the pattern at the restart point matches the action segment
                                    if (string.Compare(patternComponents[patternSegmentIndex], actionComponents[actionSegmentIndex], StringComparison.OrdinalIgnoreCase) == 0)
                                    {
                                        patternSegmentIndex++;
                                    }

                                    // Move to the next segment in the action
                                    actionSegmentIndex++;
                                }
                                else
                                {
                                    // Pattern consumed entirely - Action matches the pattern
                                    return true;
                                }
                            }
                            else
                            {
                                // No restart is possible - Action does not match pattern
                                return false;
                            }
                        }
                    }
                }

                // Did we consume the pattern entirely ?
                if (patternSegmentIndex < patternComponents.Length)
                {
                    // Pattern has not yet been scanned entirely yet we consumed the entire action - For a match, the next segment of the pattern must be one or more wildcards
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
