// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Portier.Authorization.Tests
{
    [TestClass]
    public class ActionComparerTests
    {
        [TestMethod]
        public void Wildcard_Pattern_Matches_Anything()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "*";

            string action = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/*/read";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Insights/alertRules/*";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void SlashWildcard_Pattern_Matches_Anything()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "/*";

            string action = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/*/read";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Insights/alertRules/*";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void RepeatedWildcard_Coalesce_To_One()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "Microsoft.Compute/*/*/start/action";

            string action = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/*/start/action";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            action = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_Matches_No_Segment()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "Microsoft.Compute/*";
            string action = "Microsoft.Compute";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*";
            action = "Microsoft.Compute/foo";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*/start";
            action = "Microsoft.Compute/start";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*/permissions/*/start";
            action = "Microsoft.Compute/permissions/start";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*/permissions/*";
            action = "Microsoft.Compute/permissions";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_Matches_Several_Consecutive_Segments()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "A/*/B/C/D";
            string action = "A/s/Z/C/XXX/B/C/D";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_At_End_Matches_Several_Segments()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "Microsoft.Compute/*";
            string action = "Microsoft.Compute/foo/bar";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/*";
            action = "Microsoft.Compute/foo/bar/frog";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Non_Wildcard_Pattern_Matches_Exactly()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            string action = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute";
            action = "Microsoft.Compute";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute/virtualMachines/start";
            action = "Microsoft.Compute/start";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);
        }

        [TestMethod]
        public void Comparisons_Are_OrdinalIgnoreCase()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "Microsoft.Compute/ALERTRULES/foo/BaR/froggle/StarT/acTioN";
            string action = "Microsoft.CoMpuTe/alertRules/foo/bar/froGGle/stArt/Action";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "Microsoft.Compute";
            action = "MICROSOFT.cOMpuTe";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Wildcard_Match_Can_Restart_On_False_Start()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "A/*/B";
            string action = "A/s/B/C/XXX/B";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "A/*/B";
            action = "A/s/B/B";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "A/*/B";
            action = "A/B/B/B";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);

            pattern = "A/*/B/C/D";
            action = "A/s/B/C/XXX/B/C/D";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Pattern_Longer_Than_Action_Matches_Only_If_Ends_With_Wildcard()
        {
            ActionComparer actionComparer = new ActionComparer();

            string pattern = "A/*/B/D";
            string action = "A/B";
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = "A/*/B/*";
            action = "A/B";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, action);
        }

        [TestMethod]
        public void Null_Or_Empty_Action_Or_Pattern_Never_Matches()
        {
            ActionComparer actionComparer = new ActionComparer();

            // Pattern null
            string pattern = null;
            string action = null;
            bool isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = null;
            action = string.Empty;
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = null;
            action = "A/B";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            // Pattern string.Empty
            pattern = string.Empty;
            action = null;
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = string.Empty;
            action = string.Empty;
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = string.Empty;
            action = "A/B";
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            // Pattern "A/B"
            pattern = "A/B";
            action = null;
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);

            pattern = "A/B";
            action = string.Empty;
            isEqual = actionComparer.Equals(pattern, action);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, action);
        }

        [TestMethod]
        public void GetHashCode_ThrowsArgumentNullException()
        {
            try
            {
                ActionComparer actionComparer = new ActionComparer();
                actionComparer.GetHashCode(null);
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.GetType() == typeof(ArgumentNullException), "ActionComparer.GetHashCode(null) throws ArgumentNullException");
            }
        }

        [TestMethod]
        public void GetHashCode_ReturnsStringHashCode()
        {
            ActionComparer actionComparer = new ActionComparer();

            string testString = "some ranDom STRing";
            int hashCode = actionComparer.GetHashCode(testString);
            Assert.IsTrue(hashCode == testString.GetHashCode(), "ActionComparer.GetHashCode('{0}') == '{0}.GetHashCode()");
        }
    }
}
