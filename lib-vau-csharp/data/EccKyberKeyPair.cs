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

using lib_vau_csharp.crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;

namespace lib_vau_csharp.data
{
    public class EccKyberKeyPair
    {
        internal static byte[] KyberPublicKeyEncodingHeader { get; } =
            Hex.Decode("308204B4300D060B2B0601040181B01A050602038204A100");

        public readonly AsymmetricCipherKeyPair EcdhKeyPair;
        public readonly AsymmetricCipherKeyPair KyberKeyPair;

        public EccKyberKeyPair(AsymmetricCipherKeyPair ecdhKeyPair, AsymmetricCipherKeyPair kyberKeyPair)
        {
            EcdhKeyPair = ecdhKeyPair;
            KyberKeyPair = kyberKeyPair;
        }

        public static EccKyberKeyPair GenerateKeyPair()
        {
            EllipticCurve ecCurve = EllipticCurve.GenerateEllipticCurve(EllipticCurve.SECP256R1);
            return new EccKyberKeyPair(ecCurve.GenerateKeyPair(), KyberCurve.GenerateKeyPair());
        }
    }
}
