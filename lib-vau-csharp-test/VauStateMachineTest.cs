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
using lib_vau_csharp.data;
using lib_vau_csharp_test.util;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace lib_vau_csharp_test
{
    public class VauStateMachineTest
    {
        private EccKyberKeyPair eccKyberKeyPair;
        private SignedPublicVauKeys signedPublicVauKeys;


        [SetUp]
        public void Setup()
        {
            // Prepare Keys
            eccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(@"resources\\vau_server_keys.cbor");
            byte[] privateKeyBytes = FileUtil.ReadAllBytes(@"resources\\vau-sig-key.der");
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes);

            byte[] serverAutCertificate = FileUtil.ReadAllBytes(@"resources\\vau_sig_cert.der");
            byte[] ocspResponseAutCertificate = FileUtil.ReadAllBytes(@"resources\\ocsp-response-vau-sig.der");

            VauPublicKeys vauBasicPublicKey = new VauPublicKeys(eccKyberKeyPair, "VAU Server Keys", TimeSpan.FromDays(30));
            signedPublicVauKeys = SignedPublicVauKeys.Sign(serverAutCertificate, eCPrivateKeyParameters, ocspResponseAutCertificate, 1, vauBasicPublicKey);
        }

        [Test]
        public void SimpleTest()
        {
            KEM kem = KEM.initializeKEM(KEM.KEMEngines.AesEngine, KEM.KEYSIZE_256);
            VauClientStateMachine client;
            VauServerStateMachine server;

            client = new VauClientStateMachine();
            client.initializeMachine(kem);
            server = new VauServerStateMachine(signedPublicVauKeys, eccKyberKeyPair);
            server.initializeMachine(kem);

            byte[] pMessage1 = client.generateMessage1();
            byte[] pMessage2 = server.receiveMessage1(pMessage1);
            byte[] pMessage3 = client.receiveMessage2(pMessage2);
            byte[] pMessage4 = server.receiveMessage3(pMessage3);
            client.receiveMessage4(pMessage4);
        }

    }
}
