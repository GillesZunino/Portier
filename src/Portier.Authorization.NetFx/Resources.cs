// -----------------------------------------------------------------------------------
// Copyright 2017, Gilles Zunino
// -----------------------------------------------------------------------------------

namespace Portier.Authorization
{
    using System.Resources;

    /// <summary>
    /// A strongly-typed resource class for looking up localized strings, etc.
    /// </summary>
    internal static class Resources
    {
        private static ResourceManager resourceManager;

        /// <summary>
        /// Gets the cached ResourceManager instance.
        /// </summary>
        internal static ResourceManager ResourceManager
        {
            get
            {
                if (object.ReferenceEquals(resourceManager, null))
                {
                    ResourceManager temp = new ResourceManager("Portier.Authorization.Resources.Resources", typeof(Resources).Assembly);
                    resourceManager = temp;
                }

                return resourceManager;
            }
        }

        /// <summary>
        /// Gets a localized string by name.
        /// </summary>
        /// <param name="name">Name of string resource to retrieve.</param>
        internal static string GetString(string name)
        {
            return ResourceManager.GetString(name);
        }
    }
}
