// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Portier.Authorization.Tests.Common;

namespace Portier.Authorization.Tests
{
    [TestClass]
    public class SimpleRoleDefinitionTests
    {
        [TestMethod]
        public void Invalid_RoleDefinition_Id_Throws_On_Ctor()
        {
            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "",
                        displayName: "A role without Id",
                        assignableScopes: new string[] { "/Company" },
                        permissions: new string[] {
                            "Teach/*",
                            "Hire/*",
                            "Purchase/*"
                        }
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Incorrect_RoleDefinition_Throws_On_Ctor()
        {
            // Missing scopes
            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "abcd",
                        displayName: "A role definition",
                        assignableScopes: null,
                        permissions: new string[] {
                            "Teach/*",
                            "Hire/*",
                            "Purchase/*"
                        }
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "abcd",
                        displayName: "A role definition",
                        assignableScopes: new string[] { },
                        permissions: new string[] {
                            "Teach/*",
                            "Hire/*",
                            "Purchase/*"
                        }
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            // Invalid scopes
            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "abcd",
                        displayName: "A role definition",
                        assignableScopes: new string[] { "BubbleMachine" },
                        permissions: new string[] {
                            "Teach/*",
                            "Hire/*",
                            "Purchase/*"
                        }
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );



            // Missing permissions
            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "abcd",
                        displayName: "A role definition",
                        assignableScopes: new string[] { "/BubbleMachine" },
                        permissions: null
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "abcd",
                        displayName: "A role definition",
                        assignableScopes: new string[] { "/BubbleMachine" },
                        permissions: new string[] { }
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );



            // Invalid permissions
            AssertExtensions.ShouldThrow(
                () => {
                    new SimpleRoleDefinition(
                        id: "abcd",
                        displayName: "A role definition",
                        assignableScopes: new string[] { "/BubbleMachine" },
                        permissions: new string[] {
                            "/Teach/*"
                        }
                    );
                },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }
    }
}
