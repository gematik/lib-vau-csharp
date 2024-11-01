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
using lib_vau_csharp.data;
using lib_vau_csharp_test.util;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Text;
using System.Threading.Tasks;

namespace lib_vau_csharp_test
{
    public class HandshakeTests
    {
        private static VauServer vauServer;
        private static VauClient vauClient;
        private static string url = "http://localhost:8080/";

        [SetUp]
        public void Setup()
        {
            EccKyberKeyPair eccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(@"resources\\vau_server_keys.cbor");
            byte[] privateKeyBytes = FileUtil.ReadAllBytes(@"resources\\vau-sig-key.der");
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes);

            byte[] serverAutCertificate = FileUtil.ReadAllBytes(@"resources\\vau_sig_cert.der");
            byte[] ocspResponseAutCertificate = FileUtil.ReadAllBytes(@"resources\\ocsp-response-vau-sig.der");

            VauPublicKeys vauBasicPublicKey = new VauPublicKeys(eccKyberKeyPair, "VAU Server Keys", TimeSpan.FromDays(30));
            SignedPublicVauKeys signedPublicVauKeys = SignedPublicVauKeys.Sign(serverAutCertificate, eCPrivateKeyParameters, ocspResponseAutCertificate, 1, vauBasicPublicKey);

            vauServer = new VauServer(url, signedPublicVauKeys, eccKyberKeyPair);
            vauServer.StartAsync();

        }

        [TearDown]
        public static void ShutdownServer()
        {
            if (vauServer != null)
            {
                vauServer.Stop();
            }
        }

        [Test]
        public static async Task TestSendingMessagesThroughChannel()
        {
            vauClient = new VauClient();
            bool handshakeSucceeded = await vauClient.DoHandshake(url);

            ClassicAssert.IsTrue(handshakeSucceeded);
            bool messagesExchanged = await vauClient.SendMessage(url, Encoding.UTF8.GetBytes("Hello World!"));
            ClassicAssert.IsTrue(messagesExchanged);
        }
    }
}