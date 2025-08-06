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

using System;

namespace lib_vau_csharp_test
{
    public class ReadKeysTests
    {

        [Test]
        public void TestReadPrivateSpec()
        {
            EccKyberKeyPair eccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(Constants.Paths.VauServerKeys);
            Assert.That("EC", Is.EqualTo(((ECPublicKeyParameters)eccKyberKeyPair.EcdhKeyPair.Public).AlgorithmName));
            Assert.That("EC", Is.EqualTo(((ECPrivateKeyParameters)eccKyberKeyPair.EcdhKeyPair.Private).AlgorithmName));

            Assert.That(KyberParameters.kyber768, Is.EqualTo(((KyberPrivateKeyParameters)eccKyberKeyPair.KyberKeyPair.Private).Parameters));
            Assert.That(KyberParameters.kyber768, Is.EqualTo(((KyberPublicKeyParameters)eccKyberKeyPair.KyberKeyPair.Public).Parameters));
        }

        [Test]
        public void TestSignPublicVauKeys()
        {
            VauPublicKeys vauBasicPublicKey = new VauPublicKeys(Constants.Keys.EccKyberKeyPair, "VAU Server Keys", TimeSpan.FromDays(30));
            SignedPublicVauKeys signedPublicVauKeys = SignedPublicVauKeys.Sign(Constants.Certificates.ServerAutCertificate, Constants.Keys.ECPrivateKeyParameters, Constants.Certificates.ServerAutCertificate, 1, vauBasicPublicKey);

            Assert.That(vauBasicPublicKey.Iat, Is.EqualTo(signedPublicVauKeys.ExtractVauKeys().Iat));
            Assert.That(vauBasicPublicKey.Exp, Is.EqualTo(signedPublicVauKeys.ExtractVauKeys().Exp));
        }
    }
}
