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

using lib_vau_csharp.data;
using lib_vau_csharp.exceptions;
using lib_vau_csharp.util;
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace lib_vau_csharp
{
    public class VauServer
    {
        private readonly HttpListener _listener;
        private readonly VauServerStateMachine vauServerStateMachine;
        private readonly string Cid = ConnectionId.CreateRandom().Cid;

        public VauServer(string uriPrefix, SignedPublicVauKeys signedPublicVauKeys, EccKyberKeyPair serverVauKeys)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add(uriPrefix);

            vauServerStateMachine = new VauServerStateMachine(signedPublicVauKeys, serverVauKeys);
        }

        public async Task StartAsync()
        {
            _listener.Start();
            Console.WriteLine("Listening...");
            while (_listener.IsListening)
            {
                var context = await _listener.GetContextAsync();

                if (context?.Request?.Url?.AbsolutePath == null)
                {
                    throw new VauProxyException("Failed to retrieve URL path from Context.");
                }

                switch (context.Request.Url.AbsolutePath)
                { 
                    case "/VAU":
                        await AnswerHandshake(context);
                        break;
                    default:
                        if (context.Request.Url.AbsolutePath == "/" + Cid)
                        {
                            if (context.Request.Headers.Get("Content-Type") == "application/cbor")
                            {
                                await AnswerMessage3(context);
                            }
                            else if (context.Request.Headers.Get("Content-Type") == "application/octet-stream")
                            {
                                await ReturnResponseMessage(context);
                            }
                            else throw new VauProxyException("Content Type needs to be 'cbor' or 'octet-stream'.");
                            break;
                        }
                        else
                        {
                            throw new VauProxyException("Invalid Cid.");
                        }
                }
            }
        }

        private async Task AnswerHandshake(HttpListenerContext context)
        {
            byte[] clientMessageEncoded = StreamUtils.ReadStream(context.Request.InputStream);
            var serverMessageEncoded = vauServerStateMachine.receiveMessage1(clientMessageEncoded);

            var response = context.Response;
            response.AddHeader("VAU-CID", Cid);                                 // A_24608
            await response.OutputStream.WriteAsync(serverMessageEncoded, 0, serverMessageEncoded.Length);

            response.OutputStream.Close();
        }

        private async Task AnswerMessage3(HttpListenerContext context)
        {
            byte[] clientMessageEncoded = StreamUtils.ReadStream(context.Request.InputStream);
            var serverMessageEncoded = vauServerStateMachine.receiveMessage3(clientMessageEncoded);


            var response = context.Response;
            await response.OutputStream.WriteAsync(serverMessageEncoded, 0, serverMessageEncoded.Length);

            response.OutputStream.Close();
        }

        private async Task ReturnResponseMessage(HttpListenerContext context)
        {
            byte[] clientMessageEncoded = StreamUtils.ReadStream(context.Request.InputStream);
            string clientMessage = Encoding.UTF8.GetString(vauServerStateMachine.DecryptVauMessage(clientMessageEncoded));
            Console.WriteLine($"Server received Client Message: {clientMessage}");

            byte[] serverMessageEncoded = vauServerStateMachine.EncryptVauMessage(Encoding.UTF8.GetBytes("Hello back!"));
            var response = context.Response;
            await response.OutputStream.WriteAsync(serverMessageEncoded, 0, serverMessageEncoded.Length);

            response.OutputStream.Close();
        }

        public void Stop()
        {
            _listener.Stop();
        }
    }
}
