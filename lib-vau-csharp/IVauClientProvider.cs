/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Threading.Tasks;

namespace lib_vau_csharp
{
    /// <summary>
    /// Implement this interface to provide <see cref="VauHttpClientHandler"/> with an instance of <see cref="VauClient"/>.
    /// </summary>
    public interface IVauClientProvider
    {
        /// <summary>
        /// Gets an instance of <see cref="VauClient"/> for the given <paramref name="uri"/> that is immediately usable i.e. is connected to the VAU. 
        /// May return <i>null</i> in case requests should not use the VAU.
        /// </summary>
        /// <param name="uri">The full uri for the request.</param>
        /// <returns>An instance of <see cref="VauClient"/> or <i>null</i></returns>
        /// <seealso cref="VauHttpClientHandler"/>
        Task<VauClient> GetVauClient(Uri uri);
    }
}