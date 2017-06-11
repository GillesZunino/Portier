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
    public class MemoryRoleDefinitionProviderTests
    {
        [TestMethod]
        public void Lookup_Unknown_Role_Definition_Returns_Null()
        {
            MemoryRoleDefinitionProvider staticRoleDefinitionProvider = new MemoryRoleDefinitionProvider(null);
            IRoleDefinition roleDefinition = staticRoleDefinitionProvider.GetRoleDefinitionById("foo");
            Assert.IsNull(roleDefinition, ".GetRoleDefinitionById(<unknown id>) returns null");
        }

        [TestMethod]
        public void Lookup_KnownRole_Definition_Returns_Item()
        {
            List<RoleDefinition> oneRoleDefinition = new List<RoleDefinition>()
            {
                new RoleDefinition(
                    id : "abcd",
                    displayName : "A role without Id",
                    assignableScopes : new string[] { "/Company" },
                    permissions : new string[] {
                        "Teach/*",
                        "Hire/*",
                        "Purchase/*"
                    }
                )
            };

            MemoryRoleDefinitionProvider staticRoleDefinitionProvider = new MemoryRoleDefinitionProvider(oneRoleDefinition);
            IRoleDefinition roleDefinition = staticRoleDefinitionProvider.GetRoleDefinitionById("abcd");
            Assert.IsNotNull(roleDefinition, ".GetRoleDefinitionById(<known id>) returns item");
        }

        [TestMethod]
        public void Invalid_RoleDefinition_Id_Throws_On_Ctor()
        {
            List<UnvalidatedRoleDefinition> incorrectRoleDefinitions = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "",
                    displayName : "A role without Id",
                    assignableScopes : new string[] { "/Company" },
                    permissions : new string[] {
                        "Teach/*",
                        "Hire/*",
                        "Purchase/*"
                    }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(incorrectRoleDefinitions); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Duplicate_RoleDefinition_Id_Throws_On_Ctor()
        {
            List<RoleDefinition> duplicatedRoleDefinitions = new List<RoleDefinition>()
            {
                new RoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : new string[] { "/Company" },
                    permissions : new string[] {
                        "Teach/*",
                        "Hire/*",
                        "Purchase/*"
                    }
                ),

                new RoleDefinition(
                    id : "abcd",
                    displayName : "Another role definition",
                    assignableScopes : new string[] { "/BubbleMachine" },
                    permissions : new string[] {
                        "BubbleMachine/on",
                        "BubbleMachine/off",
                        "BubbleMachine/refill"
                    }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(duplicatedRoleDefinitions); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }

        [TestMethod]
        public void Incorrect_RoleDefinition_Throws_On_Ctor()
        {
            // Missing scopes
            List<UnvalidatedRoleDefinition> badRoleDefinition = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : null,
                    permissions : new string[] {
                        "Teach/*",
                        "Hire/*",
                        "Purchase/*"
                    }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(badRoleDefinition); },
                (exception) => { return exception.GetType() == typeof(ArgumentNullException); }
            );

            badRoleDefinition = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : new string[] { },
                    permissions : new string[] {
                        "Teach/*",
                        "Hire/*",
                        "Purchase/*"
                    }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(badRoleDefinition); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            // Invalid scopes
            badRoleDefinition = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : new string[] { "BubbleMachine" },
                    permissions : new string[] {
                        "Teach/*",
                        "Hire/*",
                        "Purchase/*"
                    }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(badRoleDefinition); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );



            // Missing permissions
            badRoleDefinition = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : new string[] { "/BubbleMachine" },
                    permissions : null
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(badRoleDefinition); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );

            badRoleDefinition = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : new string[] { "/BubbleMachine" },
                    permissions : new string[] { }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(badRoleDefinition); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );



            // Invalid permissions
            badRoleDefinition = new List<UnvalidatedRoleDefinition>()
            {
                new UnvalidatedRoleDefinition(
                    id : "abcd",
                    displayName : "A role definition",
                    assignableScopes : new string[] { "/BubbleMachine" },
                    permissions : new string[] {
                        "/Teach/*"
                    }
                )
            };

            AssertExtensions.ShouldThrow(
                () => { new MemoryRoleDefinitionProvider(badRoleDefinition); },
                (exception) => { return exception.GetType() == typeof(ArgumentOutOfRangeException); }
            );
        }
    }
}
