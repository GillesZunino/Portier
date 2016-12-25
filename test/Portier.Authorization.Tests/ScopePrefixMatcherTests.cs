// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Portier.Authorization.Tests.Common;

namespace Portier.Authorization.Tests
{
    [TestClass]
    public class ScopePrefixMatcherTests
    {
        [TestMethod]
        public void Scope_Prefix_String_Must_Start_With_Delimiter()
        {
            // ScopePrefixMatcher.IsPrefixMatch(string, string)
            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch(string.Empty, null); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch("a", "b"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch("/a", "b"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );


            // ScopePrefixMatcher.IsPrefixMatch(IEnumerable<string>, string)
            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch((IEnumerable<string>) null, null); },
                (exception) => { return exception.GetType() == typeof(ArgumentNullException); }
            );

            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch(new string[] { }, null); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch(new string[] { }, "/a"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch(new string[] { "/a", "b" }, "b"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => { ScopePrefixMatcher.IsPrefixMatch(new string[] { "/a", "b" }, "b"); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Rooted_Scope_Matches_Any()
        {
            // ScopePrefixMatcher.IsPrefixMatch(string, string)
            string parent = "/";
            string child = "/Foo";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);

            child = "/Foo/Bar";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);


            // ScopePrefixMatcher.IsPrefixMatch(IEnumerable<string>, string)
            string[] parents = new string[] { "/a", "/" };
        
            child = "/Foo/Bar";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "/Foo/Bar";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));
        }

        [TestMethod]
        public void Scope_Matches_Parent()
        {
            // ScopePrefixMatcher.IsPrefixMatch(string, string)
            string parent = "/Foo";
            string child = "/Foo";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);

            parent = "/Foo/Bar";
            child = "/Foo/Bar/Froggle";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);

            // No match
            parent = "/Foo/YY";
            child = "/Foo/Bar/Froggle";
            Assert.IsFalse(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' does not match parent '{1}'", child, parent);

            parent = "/YY";
            child = "/Foo/Bar/Froggle";
            Assert.IsFalse(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' does not match parent '{1}'", child, parent);


            // ScopePrefixMatcher.IsPrefixMatch(IEnumerable<string>, string)
            string[] parents = new string[] { "/Foo", "/Froggle/Bar" };

            child = "/Foo";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "/Foo/Bar/XX";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "/Froggle/Bar/YYY";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            // No match
            child = "/ZZZ";
            Assert.IsFalse(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "/TTT/Bar/YYY";
            Assert.IsFalse(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));
        }

        [TestMethod]
        public void Scope_Comparison_Is_Ordinal_IgnoreCase()
        {
            // ScopePrefixMatcher.IsPrefixMatch(string, string)
            string parent = "/Foo";
            string child = "/FoO";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);

            parent = "/FOO/bAr";
            child = "/FoO/Bar/Froggle";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);


            // ScopePrefixMatcher.IsPrefixMatch(IEnumerable<string>, string)
            string[] parents = new string[] { "/fOo", "/FroGglE/baR" };

            child = "/FoO";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "/FOO/BAr/xX";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "/frogGLE/bAr/YYY";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));
        }

        [TestMethod]
        public void Several_Consecutive_Scope_Marker_Coalesce()
        {
            // ScopePrefixMatcher.IsPrefixMatch(string, string)
            string parent = "/FOO/////bAr";
            string child = "/FoO/Bar/Froggle";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);

            parent = "/FOO/////bAr";
            child = "/FoO/////Bar//////Froggle";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parent, child), "Child '{0}' matches parent '{1}'", child, parent);


            // ScopePrefixMatcher.IsPrefixMatch(IEnumerable<string>, string)
            string[] parents = new string[] { "/fOo///Bar", "/FroGglE/baR" };

            child = "/FOO///BAr////////xX";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));

            child = "///frogGLE/bAr///YYY";
            Assert.IsTrue(ScopePrefixMatcher.IsPrefixMatch(parents, child), "Child '{0}' matches parents '{1}'", child, string.Join(", ", parents));
        }
    }
}