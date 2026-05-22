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
using lib_vau_csharp.exceptions;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace lib_vau_csharp
{
    [DebuggerDisplay("ConnectionId: {ConnectionId}")]
    public class VauClient
    {
        private static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.KebabCaseUpper };

        private readonly HttpClient httpClient;
        private readonly VauClientStateMachine vauClientStateMachine;

        public AbstractVauStateMachine VauStateMachine => vauClientStateMachine;

        public ConnectionId ConnectionId { get; private set; }

        /// <summary>
        /// Create a new instance of the <see cref="VauClient"/> class.
        /// </summary>
        /// <param name="httpClient">A <see cref="HttpClient"/> that is configured to communicate with a record system, i.e. has the proper base address set.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public VauClient(HttpClient httpClient)
        {
            this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

            vauClientStateMachine = new VauClientStateMachine();
        }

        /// <summary>
        /// Perform handshake with the VAU.
        /// </summary>
        /// <exception cref="HttpRequestException"></exception>
        public async Task DoHandshake()
        {
            if (ConnectionId != null)
                throw new InvalidOperationException("Connection has already been established.");

            byte[] message3Encoded = await DoHandShakeStage1();
            await DoHandShakeStage2(message3Encoded);
        }

        /// <summary>
        /// Gets the VAU status for the current instance.
        /// </summary>
        /// <returns>An instance of <see cref="VauStatus"/>.</returns>
        /// <exception cref="InvalidOperationException">Thrown in case the current instance is not connected to a VAU.</exception>
        /// <exception cref="HttpRequestException"></exception>
        public async Task<VauStatus> GetStatus()
        {
            EnsureConnected();

            using var response = await SendMessage(Encoding.UTF8.GetBytes(VauRequest.Status)).ConfigureAwait(false);
            using var stream = await response.EnsureSuccessStatusCode().Content.ReadAsStreamAsync();
            return JsonSerializer.Deserialize<VauStatus>(stream, JsonSerializerOptions);
        }

        public async Task<HttpResponseMessage> SendMessage(byte[] message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            EnsureConnected();

            byte[] cborEncodedMessage = vauClientStateMachine.EncryptVauMessage(message);
            using var content = new ByteArrayContent(cborEncodedMessage);
            content.Headers.ContentType = MediaTypeHeader.Octet;
            var response = await httpClient.PostAsync(ConnectionId.Cid, content).ConfigureAwait(false);
            byte[] serverMessageEncoded = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            var decryptedResponse = vauClientStateMachine.DecryptVauMessage(serverMessageEncoded);

            VauResponse.Parse(decryptedResponse, response);
            return response;
        }

        /// <summary>
        /// Encrypts the given <paramref name="httpRequest"/> to send to the VAU.
        /// </summary>
        /// <param name="httpRequest">The request to encrypt.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException">Thrown in case the current instance is not connected to a VAU.</exception>
        public async Task EncryptRequest(HttpRequestMessage httpRequest) => await EncryptRequest(httpRequest, httpRequest.RequestUri).ConfigureAwait(false);

        /// <summary>
        /// Encrypts the given <paramref name="httpRequest"/> to send to the VAU using the provided <paramref name="uri"/>.
        /// </summary>
        /// <param name="httpRequest">The request to encrypt.</param>
        /// <param name="uri">The uri to send the <paramref name="httpRequest"/>to.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException">Thrown in case the current instance is not connected to a VAU.</exception>
        public async Task EncryptRequest(HttpRequestMessage httpRequest, Uri uri)
        {
            if (httpRequest == null)
                throw new ArgumentNullException(nameof(httpRequest));
            if (uri == null)
                throw new ArgumentNullException(nameof(uri));

            EnsureConnected();

            string request = await VauRequest.Create(httpRequest, uri);

            byte[] cborEncodedMessage = vauClientStateMachine.EncryptVauMessage(Encoding.UTF8.GetBytes(request));

            var content = new ByteArrayContent(cborEncodedMessage);
            content.Headers.ContentType = MediaTypeHeader.Octet;

            httpRequest.Headers.Accept.Add(MediaTypeHeader.Octet);
            httpRequest.Content = content;
            httpRequest.Method = HttpMethod.Post;
        }

        /// <summary>
        /// Decrypts the given <paramref name="response"/> received from the VAU.
        /// </summary>
        /// <param name="response"></param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException">Thrown in case the current instance is not connected to a VAU.</exception>
        public async Task DecryptResponse(HttpResponseMessage response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            EnsureConnected();

            byte[] encryptedResponse = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            byte[] decryptedResponse = vauClientStateMachine.DecryptVauMessage(encryptedResponse);

            VauResponse.Parse(decryptedResponse, response);
        }

        private async Task<byte[]> DoHandShakeStage1()
        {
            var message1Encoded = vauClientStateMachine.generateMessage1();

            var content = new ByteArrayContent(message1Encoded);
            content.Headers.ContentType = MediaTypeHeader.Cbor;

            using var response = await httpClient.PostAsync("VAU", content).ConfigureAwait(false);

            var message2Encoded = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

            if (!response.Headers.TryGetValues("VAU-CID", out IEnumerable<string> cidArray))
            {
                throw new VauProxyException("Failed to retrieve CID from Header.");
            }

            var cid = cidArray.First();
            ConnectionId = new ConnectionId(cid);
            return vauClientStateMachine.receiveMessage2(message2Encoded);
        }

        private async Task DoHandShakeStage2(byte[] message3Encoded)
        {
            var content2 = new ByteArrayContent(message3Encoded);
            content2.Headers.ContentType = MediaTypeHeader.Cbor;

            using var response2 = await httpClient.PostAsync(ConnectionId.Cid, content2).ConfigureAwait(false);

            byte[] message4Encoded = await response2.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            vauClientStateMachine.receiveMessage4(message4Encoded);
        }

        private void EnsureConnected()
        {
            if (ConnectionId == null)
                throw new InvalidOperationException($"No connection has been established, call {nameof(DoHandshake)} first.");
        }
    }

    public record VauStatus(string VauType, string VauVersion, string UserAuthentication, [property: JsonPropertyName("KeyID")] string KeyId, string ConnectionStart)
    {
        public bool IsTelematikIdAuthenticated(string telematikId) => UserAuthentication.Contains(telematikId);
    }
}