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
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace lib_vau_csharp
{
    /// <summary>
    /// An <see cref="HttpClientHandler"/> that transparently encrypts <see cref="HttpRequestMessage"/>s send to a record system and subsequently
    /// decrypts the <see cref="HttpResponseMessage"/>.
    /// </summary>
    /// <remarks>
    /// Note that this handler sets <see cref="HttpClientHandler.AllowAutoRedirect"/> property to <c>false</c>, so that calls to API methods like
    /// SendAuthorizationRequestSC that return 302 don't automatically call the supplied location url.
    /// Take this into account when configuring record system urls, as redirections from http to https won't work.
    /// </remarks>
    public class VauHttpClientHandler : HttpClientHandler
    {
        private readonly IVauClientProvider vauClientProvider;

        /// <summary>
        /// Creates a new instance of <see cref="VauHttpClientHandler"/>
        /// </summary>
        /// <param name="vauClientProvider">An implementation of <see cref="IVauClientProvider"/> that provides the handler with an instance of <see cref="VauClient"/>
        /// that is used to encrypt requests and decrypts responses.
        /// </param>
        /// <exception cref="ArgumentNullException"></exception>
        public VauHttpClientHandler(IVauClientProvider vauClientProvider)
        {
            this.vauClientProvider = vauClientProvider ?? throw new ArgumentNullException(nameof(vauClientProvider));

            AllowAutoRedirect = false;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var vauClient = await vauClientProvider.GetVauClient(request.RequestUri).ConfigureAwait(false);
            if (vauClient == null)
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            await vauClient.EncryptRequest(request).ConfigureAwait(false);

            request.RequestUri = new Uri(request.RequestUri!.GetLeftPart(UriPartial.Authority) + vauClient.ConnectionId.Cid);
            request.Headers.Remove("x-insurantid"); //A_25244

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                await vauClient.DecryptResponse(response).ConfigureAwait(false);
            }

            return response;
        }
    }
}
