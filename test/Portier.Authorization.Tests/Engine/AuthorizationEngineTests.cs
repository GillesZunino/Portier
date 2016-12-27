// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Portier.Authorization.Tests.Common;

namespace Portier.Authorization.Tests.Engine
{
    [TestClass]
    public class AuthorizationEngineTests
    {
        private static readonly string ObjectIdentifierClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        private static readonly string UpnClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";

        /// <summary>
        /// Role definitions for our test cases.
        /// </summary>
        private static readonly List<TestRoleDefinition> TestRoleDefinitions = new List<TestRoleDefinition>()
        {
            new TestRoleDefinition()
            {
                Id = "31D55E52-735F-49DD-A47B-E885D71FCFBE",
                DisplayName = "Director",
                AssignableScopes = new string[] { "/Daycare" },
                Permissions = new string[] {
                    "Teach/*",
                    "Hire/*",
                    "Purchase/*",
                    "Bubble/*",
                    "BubbleMachine/*"
                }
            },

            new TestRoleDefinition()
            {
                Id = "8ABDDD31-4519-4175-9034-0A5E30BD3359",
                DisplayName = "Bubble Master",
                AssignableScopes = new string[] { "/Playground", "/Daycare" },
                Permissions = new string[] {
                    "Bubble/view",
                    "Bubble/burst",
                    "BubbleMachine/on",
                    "BubbleMachine/off",
                    "BubbleMachine/refill",
                    "BubbleMachine/move",
                }
            },

            new TestRoleDefinition()
            {
                Id = "FF49EF47-3E9B-4C22-8D35-61C982D980EF",
                DisplayName = "Child",
                AssignableScopes = new string[] { "/Playground", "/Daycare" },
                Permissions = new string[] {
                    "Bubble/view",
                    "Bubble/burst"
                }
            }
        };

        /// <summary>
        /// Role assignments for our test cases.
        /// </summary>
        private static readonly List<TestRoleAssignment> TestRoleAssignments = new List<TestRoleAssignment>()
        {
            // Gives the "Director" role to user with id 94eee687-978a-434d-bd7f-dd479b3971e6 on daycare "Apple Tree"
            // A daycare director can basically perform all operations in the daycare they are assigned to
            new TestRoleAssignment()
            {
                Id = "7EB9A7B6-6136-4F3E-8051-61A5CDDF33FC",
                RoleDefinitionId = TestRoleDefinitions.Cast<TestRoleDefinition>().Single<TestRoleDefinition>((roleDefinition) => roleDefinition.DisplayName == "Director").Id,
                PrincipalId = "94eee687-978a-434d-bd7f-dd479b3971e6",
                Scope = "/DayCare/AppleTree"
            },

            // Gives the "Bubble Master" role to user with id 94eee687-978a-434d-bd7f-dd479b3971e6 on daycare "Little Bee"
            // A bubble master can perform most operations involving the bubble machine, which the exception of buying one
            new TestRoleAssignment()
            {
                Id = "C96691BD-A804-4B14-9DAC-4A433161029D",
                RoleDefinitionId = TestRoleDefinitions.Cast<TestRoleDefinition>().Single<TestRoleDefinition>((roleDefinition) => roleDefinition.DisplayName == "Bubble Master").Id,
                PrincipalId = "94eee687-978a-434d-bd7f-dd479b3971e6",
                Scope = "/Daycare/LittleBee"
            },

            // Gives the "Child" role to user with id 94eee687-978a-434d-bd7f-dd479b3971e6 on daycare "Little Bee"
            // A child can play with bubbles
            new TestRoleAssignment()
            {
                Id = "C8AD4774-74C7-4495-B366-03E6D37D11DF",
                RoleDefinitionId = TestRoleDefinitions.Cast<TestRoleDefinition>().Single<TestRoleDefinition>((roleDefinition) => roleDefinition.DisplayName == "Child").Id,
                PrincipalId = "94eee687-978a-434d-bd7f-dd479b3971e6",
                Scope = "/Daycare/LittleBee"
            }
        };

        [TestMethod]
        public void Ctor_Throws_With_Null_Providers()
        {
            AssertExtensions.ShouldThrow(
                () => { new AuthorizationEngine(null, null); },
                (exception) => { return exception.GetType() == typeof(ArgumentNullException); }
            );

            AssertExtensions.ShouldThrow(
                () => { new AuthorizationEngine(new TestRoleAssigmentProvider(TestRoleAssignments, (roleAssignment, claimsIdentity) => true), null); },
                (exception) => { return exception.GetType() == typeof(ArgumentNullException); }
            );
        }

        [TestMethod]
        public void Accessors_Return_Plausible_Values()
        {
            AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);

            Assert.IsInstanceOfType(authorizationEngine.RoleAssignmentProvider, typeof(IRoleAssignmentProvider));
            Assert.IsInstanceOfType(authorizationEngine.RoleDefinitionProvider, typeof(IRoleDefinitionProvider));
        }

        [TestMethod]
        public void CheckAccess_Throws_OnInvalidArguments()
        {
            AssertExtensions.ShouldThrow(
                () => {
                    AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);
                    authorizationEngine.CheckAccess(null, null, null);
                },
                (exception) => { return exception.GetType() == typeof(ArgumentNullException); }
            );

            AssertExtensions.ShouldThrow(
                () =>
                {
                    AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);
                    authorizationEngine.CheckAccess(GetClaimsIdentity(), null, null);
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () =>
                {
                    AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);
                    authorizationEngine.CheckAccess(GetClaimsIdentity(), "/Foo/Bar", null);
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () =>
                {
                    AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);
                    authorizationEngine.CheckAccess(GetClaimsIdentity(), "/Foo/Bar", "Walrus/pet", null);
                },
                (exception) => { return exception.GetType() == typeof(ArgumentNullException); }
            );
        }

        [TestMethod]
        public void Basic_Authorized()
        {
            AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);

            // Does user with id "94eee687-978a-434d-bd7f-dd479b3971e6" have permission to "BubbleMachine/move" in the playground of daycare "Little Bee" ? 
            ClaimsIdentity userClaimsIdentity = GetClaimsIdentity();
            string scope = "/Daycare/LittleBee/Playground";
            string permission = "BubbleMachine/move";

            AuthorizationDecision decision = authorizationEngine.CheckAccess(userClaimsIdentity, scope, permission);

            Assert.IsTrue(decision.IsAccessGranted, "User has permissions {0} on scope {1}", permission, scope);
            Assert.IsTrue(decision.SelectedRoleAssignments.Count == 1, "There is exactly one role assignment matching");
            Assert.IsTrue(decision.SelectedRoleAssignments[0].Id == "C96691BD-A804-4B14-9DAC-4A433161029D", "User is assigned role 'Bubble Master'");
        }

        [TestMethod]
        public void Basic_Non_Autorized()
        {
            AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);

            // Does user with id "94eee687-978a-434d-bd7f-dd479b3971e6" have permission to "Purchase/BubbleMachine" for daycare "Little Bee" ? 
            ClaimsIdentity userClaimsIdentity = GetClaimsIdentity();
            string scope = "/Daycare/LittleBee";
            string permission = "Purchase/BubbleMachine";

            AuthorizationDecision decision = authorizationEngine.CheckAccess(userClaimsIdentity, scope, permission);

            Assert.IsFalse(decision.IsAccessGranted, "User does not have permissions {0} on scope {1}", permission, scope);
            Assert.IsTrue(decision.SelectedRoleAssignments.Count == 0, "There are no role assignment matching");
        }

        [TestMethod]
        public void Basic_Authorized_More_Than_One_RoleAssignment_Matched()
        {
            AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);

            // Does user with id "94eee687-978a-434d-bd7f-dd479b3971e6" have permission to "Bubble/burst" in the playground of daycare "Little Bee" ? 
            ClaimsIdentity userClaimsIdentity = GetClaimsIdentity();
            string scope = "/Daycare/LittleBee/Playground";
            string permission = "Bubble/burst";

            AuthorizationDecision decision = authorizationEngine.CheckAccess(userClaimsIdentity, scope, permission, (claimsIdentity, roleAssignment, roleDefinition) => true , true);

            Assert.IsTrue(decision.IsAccessGranted, "User has permissions {0} on scope {1}", permission, scope);
            Assert.IsTrue(decision.SelectedRoleAssignments.Count == 2, "There are two role assignments matching");
            Assert.IsTrue(decision.SelectedRoleAssignments[0].Id == "C96691BD-A804-4B14-9DAC-4A433161029D", "User is assigned role 'Bubble Master'");
            Assert.IsTrue(decision.SelectedRoleAssignments[1].Id == "C8AD4774-74C7-4495-B366-03E6D37D11DF", "User is assigned role 'Child'");
        }

        [TestMethod]
        public void Basic_Authorized_More_Than_One_RoleAssignment_Returns_First_Only()
        {
            AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);

            // Does user with id "94eee687-978a-434d-bd7f-dd479b3971e6" have permission to "Bubble/burst" in the playground of daycare "Little Bee" ? 
            ClaimsIdentity userClaimsIdentity = GetClaimsIdentity();
            string scope = "/Daycare/LittleBee/Playground";
            string permission = "Bubble/burst";

            AuthorizationDecision decision = authorizationEngine.CheckAccess(userClaimsIdentity, scope, permission, (claimsIdentity, roleAssignment, roleDefinition) => true, false);

            Assert.IsTrue(decision.IsAccessGranted, "User has permissions {0} on scope {1}", permission, scope);
            Assert.IsTrue(decision.SelectedRoleAssignments.Count == 1, "There is exactly one role assignment matching");
            Assert.IsTrue(decision.SelectedRoleAssignments[0].Id == "C96691BD-A804-4B14-9DAC-4A433161029D", "User is assigned role 'Bubble Master'");
        }

        [TestMethod]
        public void Basic_Authorized_More_Than_One_RoleAssignment_Matched_Invokes_FinalCheck()
        {
            AuthorizationEngine authorizationEngine = GetAuthorizationEngine(TestRoleDefinitions, TestRoleAssignments);

            // Does user with id "94eee687-978a-434d-bd7f-dd479b3971e6" have permission to "Bubble/burst" in the playground of daycare "Little Bee" ? 
            ClaimsIdentity userClaimsIdentity = GetClaimsIdentity();
            string scope = "/Daycare/LittleBee/Playground";
            string permission = "Bubble/burst";

            // Use the final check callback to deny access to any child
            AuthorizationDecision decision = authorizationEngine.CheckAccess(userClaimsIdentity, scope, permission, (claimsIdentity, roleAssignment, roleDefinition) => ((TestRoleDefinition)roleDefinition).DisplayName != "Child", true);

            Assert.IsTrue(decision.IsAccessGranted, "User has permissions {0} on scope {1}", permission, scope);
            Assert.IsTrue(decision.SelectedRoleAssignments.Count == 1, "There is one role assignment matching");
            Assert.IsTrue(decision.SelectedRoleAssignments[0].Id == "C96691BD-A804-4B14-9DAC-4A433161029D", "User is assigned role 'Bubble Master'");
        }

        private static AuthorizationEngine GetAuthorizationEngine(List<TestRoleDefinition> roleDefinitions, List<TestRoleAssignment> roleAssignments)
        {
            TestRoleAssigmentProvider testRoleAssignementProvider = new TestRoleAssigmentProvider(
                roleAssignments,
                (roleAssignment, claimsIdentity) =>
                {
                    TestRoleAssignment testRoleAssignment = roleAssignment as TestRoleAssignment;
                    if (testRoleAssignment != null)
                    {
                        Claim objectIdClaim = claimsIdentity.Claims.FirstOrDefault<Claim>(claim => claim.Type == ObjectIdentifierClaim);
                        return objectIdClaim != null && string.Compare(objectIdClaim.Value, testRoleAssignment.PrincipalId, StringComparison.OrdinalIgnoreCase) == 0;
                    }

                    return false;
                });

            TestRoleDefinitionProvider testRoleDefinitionProvider = new TestRoleDefinitionProvider(roleDefinitions);
            return new AuthorizationEngine(testRoleAssignementProvider, testRoleDefinitionProvider);
        }

        private static ClaimsIdentity GetClaimsIdentity()
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(ObjectIdentifierClaim, "94eee687-978a-434d-bd7f-dd479b3971e6"));
            claims.Add(new Claim(UpnClaim, "bumble_bee@beedaycare.com"));

            return new ClaimsIdentity(claims);
        }
    }
}
