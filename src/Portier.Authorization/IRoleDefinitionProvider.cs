// -----------------------------------------------------------------------------------
// Copyright 2016, Gilles Zunino
// -----------------------------------------------------------------------------------

namespace Portier.Authorization
{
    /// <summary>
    /// Defines a provider capable of retrieving role definitions.
    /// </summary>
    public interface IRoleDefinitionProvider
    {
        /// <summary>
        /// Gets a role defition by its id.
        /// </summary>
        /// <param name="roleDefinitionId">Globally unique identifier.</param>
        /// <returns>Role definition if found, null otherwise.</returns>
        /// <remarks>Comparisons against id must be done using StringComparison.OrdinalIgnoreCase.</remarks>
        IRoleDefinition GetRoleDefinitionById(string id);
    }
}
