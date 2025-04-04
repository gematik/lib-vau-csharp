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
 */

using lib_vau_csharp;
using lib_vau_csharp.crypto;
using System.Collections;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using lib_vau_csharp.util;

namespace vau_proxy_csharp
{
    public class VauProxyClient
    {
        VauClientStateMachine vauClientStateMachine;
        string Cid = "";
        private static string HEADER_VAU_CID = "VAU-CID";
        private static string HEADER_VAU = "VAU";
        private static HttpClient Client = new HttpClient();

        private static String GET_VAUSTATUS = "GET /VAU-Status HTTP/1.1\r\nAccept: application / json\r\n\r\n";
        private static MediaTypeWithQualityHeaderValue cborType = new MediaTypeWithQualityHeaderValue("application/cbor");
        private static MediaTypeWithQualityHeaderValue octetType = new MediaTypeWithQualityHeaderValue("application/octet-stream");

        public VauProxyClient()
        {
            vauClientStateMachine = new VauClientStateMachine();
            KEM kem = KEM.initializeKEM(KEM.KEMEngines.AesEngine, KEM.KEYSIZE_256);
            //vauClientStateMachine.initializeMachine(kem);
        }

        public async void ConnectTo(string url)
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
                HttpResponseMessage response = null;
                response = await client.PostAsync(baseUrl + "VAU", content);
                if (response?.Headers?.TryGetValues("VAU-CID", out var cidHeader) ?? false)
                {
                    Cid = cidHeader?.ElementAt(0);
                }

                var context = await response.Content.ReadAsStreamAsync();
                byte[] message2Encoded = StreamUtils.ReadStream(context);
                return vauClientStateMachine.receiveMessage2(message2Encoded);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                throw new Exception(e.Message, e); //TODO: Specify
            }
        }

        public async Task<bool> DoHandShakeStage2(string baseUrl, HttpClient client, byte[] message3Encoded)
        {
            Console.WriteLine("Starting Handshake Stage 2...");
            var content2 = new ByteArrayContent(message3Encoded);
            content2.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");

            var response2 = client.PostAsync(baseUrl + Cid.Remove(0,1), content2).Result;

            var context2 = await response2.Content.ReadAsStreamAsync();
            byte[] message4Encoded = StreamUtils.ReadStream(context2);
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
                throw new Exception(response.ReasonPhrase);
            }
            handleCID(response);
            byte[] bytes = await response.Content.ReadAsByteArrayAsync();
            return bytes;
        }

        private void handleCID(HttpResponseMessage response)
        {
            IEnumerable<string> cidHeader = new List<string>();
            if (response?.Headers?.TryGetValues(HEADER_VAU_CID, out cidHeader) ?? false)
            {
                string[] vecStr = (string[])cidHeader;
                Cid = vecStr[0].StartsWith("/") ? vecStr[0].Remove(0, 1) : vecStr[0];
            }
        }
    }
}
