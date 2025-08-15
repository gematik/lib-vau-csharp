/*
 * Copyright 2024 gematik GmbH
 *
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
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

using lib_vau_csharp;
using lib_vau_csharp.crypto;
using System.Net.Http.Headers;
using System.Text;
using lib_vau_csharp.util;
using lib_vau_csharp.exceptions;

namespace vau_proxy_csharp
{
    public class VauProxyClient
    {
        readonly VauClientStateMachine vauClientStateMachine;
        string Cid = "";
        private static string HEADER_VAU_CID = "VAU-CID";
        private static HttpClient Client = new HttpClient();

        private static readonly string GET_VAUSTATUS = "GET /VAU-Status HTTP/1.1\r\nAccept: application / json\r\n\r\n";
        private static MediaTypeWithQualityHeaderValue octetType = new MediaTypeWithQualityHeaderValue("application/octet-stream");

        public VauProxyClient()
        {
            vauClientStateMachine = new VauClientStateMachine();
        }

        public static async Task ConnectTo(string url)
        {
            using (var client = new HttpClient())
            {
                var response = await client.GetStringAsync(url);
                Console.WriteLine(response);
            }
        }

        public async Task<bool> DoHandshake(string baseUrl)
        {
            using (var client = new HttpClient())
            {
                byte[] message3Encoded = await DoHandShakeStage1(baseUrl, client);
                return await DoHandShakeStage2(baseUrl, client, message3Encoded);
            }
        }

        public async Task<byte[]> DoHandShakeStage1(string baseUrl, HttpClient client)
        {
            try
            { 
                Console.WriteLine("Starting Handshake Stage 1...");
                var message1Encoded = vauClientStateMachine.generateMessage1();
                var content = new ByteArrayContent(message1Encoded);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");
                HttpResponseMessage? response = null;
                response = await client.PostAsync(baseUrl + "VAU", content);
                if (response?.Headers?.TryGetValues("VAU-CID", out var cidHeader) ?? false)
                {
                    Cid = cidHeader.ElementAt(0);
                    if(Cid == null)
                    {
                        throw new VauProxyException("Cid Header was null.");
                    }
                }

                if (response == null || response.Content == null)
                {
                    throw new InvalidOperationException("Response content is null.");
                }

                byte[] message2Encoded = await response.Content.ReadAsByteArrayAsync();
                return vauClientStateMachine.receiveMessage2(message2Encoded);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                throw new VauProxyException("Exception thrown at VauProxyClient in Handshake Part 1: " + e.Message, e);
            }
        }

        public async Task<bool> DoHandShakeStage2(string baseUrl, HttpClient client, byte[] message3Encoded)
        {
            Console.WriteLine("Starting Handshake Stage 2...");
            var content2 = new ByteArrayContent(message3Encoded);
            content2.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");

            var response2 = client.PostAsync(baseUrl + Cid.Remove(0,1), content2).Result;

            byte[] message4Encoded = await response2.Content.ReadAsByteArrayAsync();
            vauClientStateMachine.receiveMessage4(message4Encoded);
            return true;
        }

        public async Task<bool> TestVauStatus(string baseUrl)
        {
            byte[] encrypted = vauClientStateMachine.EncryptVauMessage(Encoding.ASCII.GetBytes(GET_VAUSTATUS));
            byte[] message5Encoded = await sendStreamAsPOST(baseUrl + Cid.Remove(0, 1), encrypted, octetType);
            byte[] pDecodedMessage = vauClientStateMachine.DecryptVauMessage(message5Encoded);
            Console.WriteLine($"Client received VAU Status: \r\n{Encoding.UTF8.GetString(pDecodedMessage)}");
            return true;
        }
        private async Task<byte[]> sendStreamAsPOST(String url, byte[] messageEncoded, MediaTypeWithQualityHeaderValue mediaType)
        {
            var content = new ByteArrayContent(messageEncoded);
            content.Headers.ContentType = mediaType;
            Client.DefaultRequestHeaders.Accept.Add(mediaType);
            var response = Client.PostAsync(url, content).Result;
            if (!response.IsSuccessStatusCode)
            {
                throw new VauProxyException("Exception thrown at VauProxyClient: " + response.ReasonPhrase);
            }
            handleCID(response);
            byte[] bytes = await response.Content.ReadAsByteArrayAsync();
            return bytes;
        }

        private void handleCID(HttpResponseMessage response)
        {
            IEnumerable<string>? cidHeader = new List<string>();
            if (response?.Headers?.TryGetValues(HEADER_VAU_CID, out cidHeader) ?? false)
            {
                string[] vecStr = (string[])cidHeader;
                Cid = vecStr[0].StartsWith('/') ? vecStr[0].Remove(0, 1) : vecStr[0];
            }
        }
    }
}
