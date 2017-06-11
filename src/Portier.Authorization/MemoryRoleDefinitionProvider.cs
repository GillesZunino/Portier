// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;

namespace Portier.Authorization
{
    /// <summary>
    /// A role definition provider capable of resolving role definitions from a static set of role definitions completely held in memory.
    /// </summary>
    public class MemoryRoleDefinitionProvider : IRoleDefinitionProvider
    {
        /// <summary>
        /// Gets or sets the role definitions the provider resolves from.
        /// </summary>
        public ConcurrentDictionary<string, IRoleDefinition> AllRoleDefinitions { get; private set; }

        /// <summary>
        /// Creates a new instance of StaticRoleDefinitionProvider.
        /// </summary>
        /// <param name="allRoleDefinitions">List of role definition the provider will use to resolve roles.</param>
        public MemoryRoleDefinitionProvider(IEnumerable<IRoleDefinition> allRoleDefinitions)
        {
            AllRoleDefinitions = IndexRoleDefinitionsById(allRoleDefinitions);
        }

        /// <summary>
        /// Gets a role defition by id.
        /// </summary>
        /// <param name="roleDefinitionId">Globally unique identifier.</param>
        /// <returns>Role definition if found, null otherwise.</returns>
        /// <remarks>Comparisons against id are be done using StringComparison.OrdinalIgnoreCase.</remarks>
        public IRoleDefinition GetRoleDefinitionById(string id)
        {
            if (AllRoleDefinitions.TryGetValue(id, out IRoleDefinition roleDefinition))
            {
                return roleDefinition;
            }

            return null;
        }

        private static ConcurrentDictionary<string, IRoleDefinition> IndexRoleDefinitionsById(IEnumerable<IRoleDefinition> allRoleDefinitions)
        {
            ConcurrentDictionary<string, IRoleDefinition> formattedRoleDefinitions = new ConcurrentDictionary<string, IRoleDefinition>(StringComparer.OrdinalIgnoreCase);

            if (allRoleDefinitions != null)
            {
                foreach (IRoleDefinition roleDefinition in allRoleDefinitions)
                {
                    if (roleDefinition != null)
                    {
                        Validators.ValidateRoleDefinition(roleDefinition);

                        // Role definition id must be unique
                        if (!formattedRoleDefinitions.TryAdd(roleDefinition.Id, roleDefinition))
                        {
                            throw new ArgumentOutOfRangeException(nameof(allRoleDefinitions), string.Format(CultureInfo.CurrentCulture, "Role definition with Id '{0}' already exists", roleDefinition.Id));
                        }
                    }
                }
            }

            return formattedRoleDefinitions;
        }
    }
}