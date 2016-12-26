// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Portier.Authorization.Tests.Common
{
    /// <summary>
    /// Various assertions to facilitate testing.
    /// </summary>
    internal static class AssertExtensions
    {
        /// <summary>
        /// Ensures that the given action throws as part of the execution.
        /// </summary>
        /// <param name="action">Action to execute.</param>
        /// <param name="exceptionCheck">Function responsible for checking the thrown exception is expected.</param>
        public static void ShouldThrow(Action action, Func<Exception, bool> exceptionCheck)
        {
            try
            {
                action();

                Assert.Fail("Exception was not thrown");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(exceptionCheck(ex), "Exception was thrown but did not match expectations - {0}", ex);
            }
        }
    }
}
