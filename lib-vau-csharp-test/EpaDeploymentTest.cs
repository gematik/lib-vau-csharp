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

using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

using lib_vau_csharp.util;

namespace lib_vau_csharp_test
{
    [Explicit]
    public class EpaDeploymentTest
    {
        private static string HEADER_VAU_CID = "VAU-CID";
        private static string HEADER_VAU = "VAU";
        private static HttpClient Client = new HttpClient();
        private VauClientStateMachine vauClientStateMachine;

        private String epaCID = "";

        [SetUp]
        public void Setup()
        {
            vauClientStateMachine = new VauClientStateMachine();
            Kem.initializeKem(Kem.KemEngines.AesEngine, Kem.KEYSIZE_256);
        }

        [Test]
        public async Task TestEpaDeployment()
        {
            await DoHandshake();
            await DoMessageTest();
        }

        private async Task DoHandshake()
        {
            var message1Encoded = vauClientStateMachine.generateMessage1();
            byte[] message2Encoded = await SendStreamAsPost(Constants.EpaDeploymentUrl + HEADER_VAU, message1Encoded, MediaTypeHeader.Cbor);

            byte[] message3Encoded = vauClientStateMachine.receiveMessage2(message2Encoded);
            byte[] message4Encoded = await SendStreamAsPost(Constants.EpaDeploymentUrl + epaCID, message3Encoded, MediaTypeHeader.Cbor);
            vauClientStateMachine.receiveMessage4(message4Encoded);    
        }

        private async Task DoMessageTest() 
        {
            byte[] encrypted = vauClientStateMachine.EncryptVauMessage(Encoding.ASCII.GetBytes(VauRequest.Status));
            byte[] message5Encoded = await SendStreamAsPost(Constants.EpaDeploymentUrl + epaCID, encrypted, MediaTypeHeader.Octet);
            byte[] pDecodedMessage = vauClientStateMachine.DecryptVauMessage(message5Encoded);
            Console.WriteLine($"Client received VAU Status: \r\n{Encoding.UTF8.GetString(pDecodedMessage)}");
        }

        private void HandleCid(HttpResponseMessage response)
        {
            IEnumerable<string> cidHeader = new List<string>();
            if (response?.Headers?.TryGetValues(HEADER_VAU_CID, out cidHeader) ?? false)
            {
                string[] vecStr = (string[])cidHeader;
                epaCID = vecStr[0].StartsWith("/") ? vecStr[0].Remove(0, 1) : vecStr[0];
            }
        }

        private async Task<byte[]> SendStreamAsPost(String url, byte[] messageEncoded, MediaTypeWithQualityHeaderValue mediaType)
        {
            var content = new ByteArrayContent(messageEncoded);
            content.Headers.ContentType = mediaType;
            Client.DefaultRequestHeaders.Accept.Add(mediaType);
            var response = Client.PostAsync(url, content).Result;
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(response.ReasonPhrase);
            }
            HandleCid(response);
            byte[] bytes = await response.Content.ReadAsByteArrayAsync();
            return bytes;
        }
    }
}