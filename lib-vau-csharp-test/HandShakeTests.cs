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
using lib_vau_csharp.data;

using NUnit.Framework;
using NUnit.Framework.Legacy;

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
            VauPublicKeys vauBasicPublicKey = new VauPublicKeys(Constants.Keys.EccKyberKeyPair, "VAU Server Keys", TimeSpan.FromDays(30));
            SignedPublicVauKeys signedPublicVauKeys = SignedPublicVauKeys.Sign(Constants.Certificates.ServerAutCertificate, Constants.Keys.ECPrivateKeyParameters, Constants.Certificates.OcspResponseAutCertificate, 1, vauBasicPublicKey);

            vauServer = new VauServer(url, signedPublicVauKeys, Constants.Keys.EccKyberKeyPair);
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
        public static void TestSendingMessagesThroughChannel()
        {
            vauClient = new VauClient();
            bool handshakeSucceeded = vauClient.DoHandshake(url).Result;

            ClassicAssert.IsTrue(handshakeSucceeded);
            bool messagesExchanged = vauClient.SendMessage(url, Encoding.UTF8.GetBytes("Hello World!")).Result;
            ClassicAssert.IsTrue(messagesExchanged);
        }
    }
}