// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Portier.Authorization.Tests.Common;

namespace Portier.Authorization.Tests
{
    [TestClass]
    public class PermissionPatternMatcherTests
    {
        [TestMethod]
        public void Permission_Cannot_Contain_Wildcards()
        {
            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("*", "Microsoft.Compute/*/read"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Pattern_Cannot_Start_With_Delimiter()
        {
            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("/*", "Microsoft.Compute/virtualMachines/start/action"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("/", "Microsoft.Compute/virtualMachines/start/action"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("/////", "Microsoft.Compute/virtualMachines/start/action"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Permission_Cannot_Start_With_Delimiter()
        {
            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("/////", "/"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("/////", "////"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("Bubble/burst", "/xxx"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Trailing_Delimiter_Are_Ignored()
        {
            string pattern = "Microsoft.Compute/Foo";
            string permission = "Microsoft.Compute/Foo/";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/Foo//";
            permission = "Microsoft.Compute/Foo///";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "a//";
            permission = "a";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "a//";
            permission = "a/";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "a//";
            permission = "a//////";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Wildcard_Pattern_Matches_Anything()
        {
            string pattern = "*";

            string permission = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            permission = "Microsoft.Compute/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void RepeatedWildcard_Coalesce_To_One()
        {
            string pattern = "Microsoft.Compute/*/*/start/action";

            string permission = "Microsoft.Compute/virtualMachines/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            permission = "Microsoft.Compute/start/action";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            permission = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Wildcard_Matches_No_Segment()
        {
            string pattern = "Microsoft.Compute/*";
            string permission = "Microsoft.Compute";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/*";
            permission = "Microsoft.Compute/foo";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/*/start";
            permission = "Microsoft.Compute/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/*/permissions/*/start";
            permission = "Microsoft.Compute/permissions/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/*/permissions/*";
            permission = "Microsoft.Compute/permissions";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Wildcard_Matches_Several_Consecutive_Segments()
        {
            string pattern = "A/*/B/C/D";
            string permission = "A/s/Z/C/XXX/B/C/D";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Wildcard_At_End_Matches_Several_Segments()
        {
            string pattern = "Microsoft.Compute/*";
            string permission = "Microsoft.Compute/foo/bar";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/*";
            permission = "Microsoft.Compute/foo/bar/frog";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Non_Wildcard_Pattern_Matches_Exactly()
        {
            string pattern = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            string permission = "Microsoft.Compute/alertRules/foo/bar/froggle/start/action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute";
            permission = "Microsoft.Compute";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute/virtualMachines/start";
            permission = "Microsoft.Compute/start";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Comparisons_Are_OrdinalIgnoreCase()
        {
            string pattern = "Microsoft.Compute/ALERTRULES/foo/BaR/froggle/StarT/acTioN";
            string permission = "Microsoft.CoMpuTe/alertRules/foo/bar/froGGle/stArt/Action";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "Microsoft.Compute";
            permission = "MICROSOFT.cOMpuTe";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Wildcard_Match_Can_Restart_On_False_Start()
        {
            string pattern = "A/*/B";
            string permission = "A/s/B/C/XXX/B";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "A/*/B";
            permission = "A/s/B/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "A/*/B";
            permission = "A/B/B/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);

            pattern = "A/*/B/C/D";
            permission = "A/s/B/C/XXX/B/C/D";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Pattern_Longer_Than_Permission_Matches_Only_If_Ends_With_Wildcard()
        {
            string pattern = "A/*/B/D";
            string permission = "A/B";
            bool isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsFalse(isEqual, "'{0}' does not match '{1}'", pattern, permission);

            pattern = "A/*/B/*";
            permission = "A/B";
            isEqual = PermissionPatternMatcher.IsMatch(pattern, permission);
            Assert.IsTrue(isEqual, "'{0}' matches '{1}'", pattern, permission);
        }

        [TestMethod]
        public void Pattern_And_Permission_Must_Not_Be_Null_Or_Empty()
        {
            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch(null, null); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch(null, string.Empty); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch(null, "A/B"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch(string.Empty, null); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch(string.Empty, string.Empty); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch(string.Empty, "A/B"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("A/B", null); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { PermissionPatternMatcher.IsMatch("A/B", string.Empty); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }
    }
}
