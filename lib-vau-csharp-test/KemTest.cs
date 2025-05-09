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
using lib_vau_csharp_test.util;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace lib_vau_csharp_test
{
    public class KemTest
    {

        [Test]
        public void TestKem()
        {
            EllipticCurve ecCurve = EllipticCurve.GenerateEllipticCurve(EllipticCurve.SECP256R1);
            AsymmetricCipherKeyPair ecdhKeyPair = ecCurve.GenerateKeyPair();
            AsymmetricCipherKeyPair kyberKeyPair = KyberCurve.GenerateKeyPair();
            KEM.EncapsulateMessage((ECPublicKeyParameters)ecdhKeyPair.Public, ((KyberPublicKeyParameters)kyberKeyPair.Public));
        }

        [Test]
        public void TestHandshake()
        {
            doHandShakeTest(false);
        }

        [Test]
        public void TestHandshakePU()
        {
            doHandShakeTest(true);
        }

        public void doHandShakeTest(bool isPu)
        {

            EccKyberKeyPair eccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(@"resources\\vau_server_keys.cbor");
            byte[] privateKeyBytes = FileUtil.ReadAllBytes(@"resources\\vau-sig-key.der");
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes);

            byte[] serverAutCertificate = FileUtil.ReadAllBytes(@"resources\\vau_sig_cert.der");
            byte[] ocspResponseAutCertificate = FileUtil.ReadAllBytes(@"resources\\ocsp-response-vau-sig.der");

            VauPublicKeys vauBasicPublicKey = new VauPublicKeys(eccKyberKeyPair, "VAU Server Keys", TimeSpan.FromDays(30));
            SignedPublicVauKeys signedPublicVauKeys = SignedPublicVauKeys.Sign(serverAutCertificate, eCPrivateKeyParameters, ocspResponseAutCertificate, 1, vauBasicPublicKey);

            VauServerStateMachine vauServerStateMachine = new VauServerStateMachine(signedPublicVauKeys, eccKyberKeyPair);
            vauServerStateMachine.isPu = isPu;
            VauClientStateMachine vauClientStateMachine = new VauClientStateMachine();
            vauClientStateMachine.isPu = isPu;

            //Generate Message 1
            byte[] message1Encoded = vauClientStateMachine.generateMessage1();
            byte[] message2Encoded = vauServerStateMachine.receiveMessage1(message1Encoded);
            byte[] message3Encoded = vauClientStateMachine.receiveMessage2(message2Encoded);
            byte[] message4Encoded = vauServerStateMachine.receiveMessage3(message3Encoded);
            vauClientStateMachine.receiveMessage4(message4Encoded);

            //Encrypt/Decrypt
            byte[] encryptedVauServerMessage = vauServerStateMachine.EncryptVauMessage(Encoding.ASCII.GetBytes("Hello World"));
            byte[] decryptedVauServerMessage = vauClientStateMachine.DecryptVauMessage(encryptedVauServerMessage);
            ClassicAssert.AreEqual("Hello World", Encoding.UTF8.GetString(decryptedVauServerMessage));

            byte[] encryptedVauServerMessage2 = vauClientStateMachine.EncryptVauMessage(Encoding.ASCII.GetBytes("Hello World"));
            byte[] decryptedVauServerMessage2 = vauServerStateMachine.DecryptVauMessage(encryptedVauServerMessage2);
            ClassicAssert.AreEqual("Hello World", Encoding.UTF8.GetString(decryptedVauServerMessage2));
        }
    }
}
