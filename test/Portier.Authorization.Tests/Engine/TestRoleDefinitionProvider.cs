// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;

namespace Portier.Authorization.Tests.Engine
{
    /// <summary>
    /// A generic Role Definition Provider for testing.
    /// </summary>
    internal class TestRoleDefinitionProvider : IRoleDefinitionProvider
    {
        private Dictionary<string, IRoleDefinition> AllRoleDefinitions { get; set; }

        public TestRoleDefinitionProvider(IEnumerable<IRoleDefinition> allRoleDefinitions)
        {
            AllRoleDefinitions = FormatRoleDefinitions(allRoleDefinitions);
        }

        public IRoleDefinition GetRoleDefinitionById(string id)
        {
            IRoleDefinition roleDefinition;
            if (AllRoleDefinitions.TryGetValue(id, out roleDefinition))
            {
                return roleDefinition;
            }

            return null;
        }

        private static Dictionary<string, IRoleDefinition> FormatRoleDefinitions(IEnumerable<IRoleDefinition> allRoleDefinitions)
        {
            Dictionary<string, IRoleDefinition> formattedRoleDefinitions = new Dictionary<string, IRoleDefinition>(StringComparer.OrdinalIgnoreCase);

            if (allRoleDefinitions != null)
            {
                foreach (IRoleDefinition roleDefinition in allRoleDefinitions)
                {
                    IRoleDefinition existingRoleDefinition = null;
                    if (formattedRoleDefinitions.TryGetValue(roleDefinition.Id, out existingRoleDefinition))
                    {
                        throw new ArgumentOutOfRangeException(nameof(allRoleDefinitions), string.Format(CultureInfo.CurrentCulture, "Role definition with '{0}' has already been added to the dictionary", roleDefinition.Id));
                    }
                    else
                    {
                        formattedRoleDefinitions[roleDefinition.Id] = roleDefinition;
                    }
                }
            }

            return formattedRoleDefinitions;
        }
    }
}
