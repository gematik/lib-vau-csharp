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
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace lib_vau_csharp
{
    public class VauRequest
    {
        private const string CrLf = "\r\n";  

        public const string Status = "GET /VAU-Status HTTP/1.1\r\nAccept: application / json\r\n\r\n";

        /// <summary>
        /// Creates the inner http request to send to the VAU from the provided <paramref name="httpRequestMessage"/>.  
        /// </summary>
        /// <param name="httpRequestMessage"></param>
        /// <param name="uri"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static async Task<string> Create(HttpRequestMessage httpRequestMessage, Uri uri)
        {
            if (httpRequestMessage == null)
                throw new ArgumentNullException(nameof(httpRequestMessage));
            if (uri == null)
                throw new ArgumentNullException(nameof(uri));

            string headers = String.Join(CrLf, httpRequestMessage.Headers.Select(x => $"{x.Key}: {x.Value.First()}"));
            
            string payload = null, contentHeaders = null;
            if (httpRequestMessage.Content != null )
            {
                payload = await httpRequestMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
                contentHeaders = String.Join(CrLf, httpRequestMessage.Content.Headers.Select(x => $"{x.Key}: {x.Value.First()}"));
                if (contentHeaders.Length > 0)
                    contentHeaders += CrLf;
            }

            string request = $"{httpRequestMessage.Method.Method} {uri.LocalPath} HTTP/{httpRequestMessage.Version}{CrLf}" +
                             $"{headers}{CrLf}" +
                             $"{contentHeaders}" +
                             $"{CrLf}";

            if (payload != null)
                request += payload;

            return request;
        }
    }
}