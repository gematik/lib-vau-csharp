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
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

using lib_vau_csharp.util;

namespace lib_vau_csharp
{
    public class VauResponse
    {
        private const int StatusCodeIndex = 1;
        private const int ReasonPhraseIndex = 2;

        private const int CrLfLength = 2;

        private static readonly char[] HeaderSplit = [':'];

        /// <summary>
        /// Parses the given <paramref name="decryptedResponse"/> into the given <paramref name="httpResponseMessage"/>.
        /// </summary>
        /// <param name="decryptedResponse"></param>
        /// <param name="httpResponseMessage"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Parse(byte[] decryptedResponse, HttpResponseMessage httpResponseMessage)
        {
            if (decryptedResponse == null)
                throw new ArgumentNullException(nameof(decryptedResponse));
            if (httpResponseMessage == null)
                throw new ArgumentNullException(nameof(httpResponseMessage));

            using var memoryStream = new MemoryStream(decryptedResponse);
            using var reader = new StreamReader(memoryStream);

            int bytesRead = 0; //Keep track of the number of bytes read from the stream to read the content later, since not all responses contain a 'Content-Length' header which we could use otherwise 
            int i = 0;

            var contentHeaders = new Dictionary<string, string>();

            while (bytesRead < memoryStream.Length)
            {
                string line = reader.ReadLine();
                bytesRead += Encoding.UTF8.GetByteCount(line) + CrLfLength;

                if (i++ == 0)
                {
                    if (line.StartsWith("HTTP"))
                    {
                        string[] status = line.Split(' ');
                        if (Enum.TryParse(status[StatusCodeIndex], true, out HttpStatusCode statusCode))
                            httpResponseMessage.StatusCode = statusCode;

                        httpResponseMessage.ReasonPhrase = status[ReasonPhraseIndex];
                        continue;
                    }

                    //Not sure if we can get here in a production env, the TestSendingMessagesThroughChannel test expects this work though 
                    break;
                }

                if (String.IsNullOrWhiteSpace(line))
                {
                    break;
                }

                string[] headerNameValue = line.Split(HeaderSplit, 2);
                string name = headerNameValue[0].Trim();

                if (HttpResponseHeaderNames.IsContentHeader(name))
                {
                    contentHeaders.Add(name, headerNameValue[1].Trim());
                }
                else if (HttpResponseHeaderNames.All.Contains(name))
                {
                    string value = headerNameValue[1].Trim();
                    httpResponseMessage.Headers.Add(name, value);
                }
            }

            long contentSize = memoryStream.Length - bytesRead;
            if (contentSize <= 0)
                return;

            httpResponseMessage.Content = new ByteArrayContent(decryptedResponse, bytesRead, (int)contentSize);
            foreach (var contentHeader in contentHeaders)
            {
                httpResponseMessage.Content.Headers.Add(contentHeader.Key, contentHeader.Value.Trim());
            }
        }
    }
}