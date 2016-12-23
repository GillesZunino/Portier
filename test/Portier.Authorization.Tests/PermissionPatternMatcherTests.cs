// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Portier.Authorization.Tests
{
    [TestClass]
    public class PermissionPatternMatcherTests
    {
        [TestMethod]
        public void Wildcard_Pattern_Matches_Anything()
        {
            string pattern = "*";

            string action = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/*/read";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Insights/alertRules/*";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void SlashWildcard_Pattern_Matches_Anything()
        {
            string pattern = "/*";

            string action = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/*/read";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Insights/alertRules/*";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void RepeatedWildcard_Coalesce_To_One()
        {
            string pattern = "Microsoft.Compute/*/*/start/action";

            string action = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/*/start/action";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_Matches_No_Segment()
        {
            string pattern = "Microsoft.Compute/*";
            string action = "Microsoft.Compute";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*";
            action = "Microsoft.Compute/foo";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*/start";
            action = "Microsoft.Compute/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*/permissions/*/start";
            action = "Microsoft.Compute/permissions/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*/permissions/*";
            action = "Microsoft.Compute/permissions";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_Matches_Several_Consecutive_Segments()
        {
            string pattern = "A/*/B/C/D";
            string action = "A/s/Z/C/XXX/B/C/D";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_At_End_Matches_Several_Segments()
        {
            string pattern = "Microsoft.Compute/*";
            string action = "Microsoft.Compute/foo/bar";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*";
            action = "Microsoft.Compute/foo/bar/frog";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Non_Wildcard_Pattern_Matches_Exactly()
        {
            string pattern = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            string action = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute";
            action = "Microsoft.Compute";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/virtualMachines/start";
            action = "Microsoft.Compute/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);
        }

        [TestMethod]
        public void Comparisons_Are_OrdinalIgnoreCase()
        {
            string pattern = "Microsoft.Compute/ALERTRULES/foo/BaR/froggle/StarT/acTioN";
            string action = "Microsoft.CoMpuTe/alertRules/foo/bar/froGGle/stArt/Action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute";
            action = "MICROSOFT.cOMpuTe";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_Match_Can_Restart_On_False_Start()
        {
            string pattern = "A/*/B";
            string action = "A/s/B/C/XXX/B";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "A/*/B";
            action = "A/s/B/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "A/*/B";
            action = "A/B/B/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "A/*/B/C/D";
            action = "A/s/B/C/XXX/B/C/D";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Pattern_Longer_Than_Action_Matches_Only_If_Ends_With_Wildcard()
        {
            string pattern = "A/*/B/D";
            string action = "A/B";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = "A/*/B/*";
            action = "A/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Null_Or_Empty_Action_Or_Pattern_Never_Matches()
        {
            // Pattern null
            string pattern = null;
            string action = null;
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = null;
            action = string.Empty;
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = null;
            action = "A/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            // Pattern string.Empty
            pattern = string.Empty;
            action = null;
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = string.Empty;
            action = string.Empty;
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = string.Empty;
            action = "A/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            // Pattern "A/B"
            pattern = "A/B";
            action = null;
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = "A/B";
            action = string.Empty;
            isEqual = PermissionPatternMatcher.IsMatch(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);
        }
    }
}
