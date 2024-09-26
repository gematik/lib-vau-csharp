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
using lib_vau_csharp_test.util;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using System;

namespace lib_vau_csharp_test
{
    public class ReadKeysTests
    {

        [Test]
        public void TestReadPrivateSpec()
        {
            EccKyberKeyPair eccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(@"resources\\vau_server_keys.cbor");

            Assert.AreEqual("EC", ((ECPublicKeyParameters)eccKyberKeyPair.EcdhKeyPair.Public).AlgorithmName);
            Assert.AreEqual("EC", ((ECPrivateKeyParameters)eccKyberKeyPair.EcdhKeyPair.Private).AlgorithmName);

            Assert.AreEqual(KyberParameters.kyber768, ((KyberPrivateKeyParameters)eccKyberKeyPair.KyberKeyPair.Private).Parameters);
            Assert.AreEqual(KyberParameters.kyber768, ((KyberPublicKeyParameters)eccKyberKeyPair.KyberKeyPair.Public).Parameters);
        }

        [Test]
        public void TestSignPublicVauKeys()
        {
            EccKyberKeyPair eccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(@"resources\\vau_server_keys.cbor");
            byte[] privateKeyBytes = FileUtil.ReadAllBytes(@"resources\\vau-sig-key.der");
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes);

            byte[] serverAutCertificate = FileUtil.ReadAllBytes(@"resources\\vau_sig_cert.der");
            byte[] ocspResponseAutCertificate = FileUtil.ReadAllBytes(@"resources\\ocsp-response-vau-sig.der");

            VauPublicKeys vauBasicPublicKey = new VauPublicKeys(eccKyberKeyPair, "VAU Server Keys", TimeSpan.FromDays(30));
            SignedPublicVauKeys signedPublicVauKeys = SignedPublicVauKeys.Sign(serverAutCertificate, eCPrivateKeyParameters, ocspResponseAutCertificate, 1, vauBasicPublicKey);

            Assert.AreEqual(vauBasicPublicKey.Iat, signedPublicVauKeys.ExtractVauKeys().Iat);
            Assert.AreEqual(vauBasicPublicKey.Exp, signedPublicVauKeys.ExtractVauKeys().Exp);
        }
    }
}
