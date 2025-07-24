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

using lib_vau_csharp.data;
using lib_vau_csharp.util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;


namespace lib_vau_csharp
{
    public class VauClient
    {
        readonly VauClientStateMachine vauClientStateMachine;
        ConnectionId Cid;

        public VauClient()
        {
            vauClientStateMachine = new VauClientStateMachine();
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
            var message1Encoded = vauClientStateMachine.generateMessage1();

            var content = new ByteArrayContent(message1Encoded);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");
            var response = await client.PostAsync(baseUrl + "VAU", content);

            var context = await response.Content.ReadAsStreamAsync();

            IEnumerable<string> cidArray;
            if (!response.Headers.TryGetValues("VAU-CID", out cidArray))
            {
                throw new Exception(); // TODO
            }

            var cid = cidArray.First();
            Cid = new ConnectionId(cid);
            byte[] message2Encoded = StreamUtils.ReadStream(context);
            return vauClientStateMachine.receiveMessage2(message2Encoded);
        }

        public async Task<bool> DoHandShakeStage2(string baseUrl, HttpClient client, byte[] message3Encoded)
        {
            var content2 = new ByteArrayContent(message3Encoded);
            content2.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");

            var response2 = await client.PostAsync(baseUrl + Cid.Cid, content2);

            var context2 = await response2.Content.ReadAsStreamAsync();
            byte[] message4Encoded = StreamUtils.ReadStream(context2);
            vauClientStateMachine.receiveMessage4(message4Encoded);
            return true;
        }

        public async Task<bool> SendMessage(string baseUrl, byte[] message)
        {
            using (var client = new HttpClient())
            {
                byte[] cborEncodedMessage = vauClientStateMachine.EncryptVauMessage(message);
                var content = new ByteArrayContent(cborEncodedMessage);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                var response = await client.PostAsync(baseUrl + Cid.Cid, content);
                var context = await response.Content.ReadAsStreamAsync();
                byte[] serverMessageEncoded = StreamUtils.ReadStream(context);
                string serverMessage = Encoding.UTF8.GetString(vauClientStateMachine.DecryptVauMessage(serverMessageEncoded));
                Console.WriteLine($"Client received ServerMessage: {serverMessage}");
                return response.StatusCode == System.Net.HttpStatusCode.OK;
            }
        }
    }
}
