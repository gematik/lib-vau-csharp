﻿/*
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
using lib_vau_csharp.data;

using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace lib_vau_csharp_test
{
    public class EpaDeploymentTest
    {
        private static string epaUrl = "http://localhost:443/";
        private static string HEADER_VAU_CID = "VAU-CID";
        private static string HEADER_VAU = "VAU";
        private static HttpClient Client = new HttpClient();
        private VauClientStateMachine vauClientStateMachine;

        private static String GET_VAUSTATUS = "GET /VAU-Status HTTP/1.1\r\nAccept: application / json\r\n\r\n";
        private static MediaTypeWithQualityHeaderValue cborType =  new MediaTypeWithQualityHeaderValue("application/cbor");
        private static MediaTypeWithQualityHeaderValue octetType = new MediaTypeWithQualityHeaderValue("application/octet-stream");
        private String epaCID = "";

        [SetUp]
        public void Setup()
        {
            vauClientStateMachine = new VauClientStateMachine();
            KEM.initializeKEM(KEM.KEMEngines.AesEngine, KEM.KEYSIZE_256);
        }

         // [Test]
        public async Task TestEpaDeployment()
        {
            await DoHandshake();
            await DoMessageTest();
        }

        private async Task DoHandshake()
        {
            var message1Encoded = vauClientStateMachine.generateMessage1();
            byte[] message2Encoded = await sendStreamAsPOST(epaUrl + HEADER_VAU, message1Encoded, cborType);

            byte[] message3Encoded = vauClientStateMachine.receiveMessage2(message2Encoded);
            byte[] message4Encoded = await sendStreamAsPOST(epaUrl + epaCID, message3Encoded, cborType);
            vauClientStateMachine.receiveMessage4(message4Encoded);    
        }

        private async Task DoMessageTest() {
            byte[] encrypted = vauClientStateMachine.EncryptVauMessage(Encoding.ASCII.GetBytes(GET_VAUSTATUS));
            byte[] message5Encoded = await sendStreamAsPOST(epaUrl + epaCID, encrypted, octetType);
            byte[] pDecodedMessage = vauClientStateMachine.DecryptVauMessage(message5Encoded);
            Console.WriteLine($"Client received VAU Status: \r\n{Encoding.UTF8.GetString(pDecodedMessage)}");
        }

        private void handleCID(HttpResponseMessage response)
        {
            IEnumerable<string> cidHeader = new List<string>();
            if (response?.Headers?.TryGetValues(HEADER_VAU_CID, out cidHeader) ?? false)
            {
                string[] vecStr = (string[])cidHeader;
                epaCID = vecStr[0].StartsWith("/") ? vecStr[0].Remove(0, 1) : vecStr[0];
            }
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
    }
}
