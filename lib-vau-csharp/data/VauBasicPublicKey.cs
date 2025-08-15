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

using lib_vau_csharp.exceptions;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using System;

namespace lib_vau_csharp.data
{
    public class VauBasicPublicKey
    {
        public VauEccPublicKey EcdhPublicKey { get; private set; }
        public byte[] KyberPublicKeyBytes { get; set; }

        public VauBasicPublicKey(EccKyberKeyPair keyPair)
        {
            EcdhPublicKey = new VauEccPublicKey((ECPublicKeyParameters)keyPair.EcdhKeyPair.Public);
            KyberPublicKeyBytes = extractCompactKyberPublicKey(keyPair.KyberKeyPair);
        }

        [JsonConstructor]
        public VauBasicPublicKey(VauEccPublicKey ecdhPublicKey, byte[] kyberPublicKeyBytes)
        {
            EcdhPublicKey = ecdhPublicKey;
            KyberPublicKeyBytes = kyberPublicKeyBytes;
        }


        private static byte[] extractCompactKyberPublicKey(AsymmetricCipherKeyPair kyberKeyPair)
        {
            try
            {
                byte[] verbosePublicKey = ((KyberPublicKeyParameters)kyberKeyPair.Public).GetEncoded();
                if (verbosePublicKey.Length == 1208)
                {
                    Asn1InputStream asn1InputStream = new Asn1InputStream(verbosePublicKey);
                    var sequence = (Asn1Sequence)asn1InputStream.ReadObject();
                    return ((DerBitString)sequence[1]).GetBytes();
                }

                return verbosePublicKey;
            }
            catch (Exception e)
            {
                throw new KyberException("Could not extract Kyber public key from key pair", e);
            }
        }

        public KyberPublicKeyParameters ToKyberPublicKey()
        {
            byte[] x509certData = Arrays.Concatenate(EccKyberKeyPair.KyberPublicKeyEncodingHeader, KyberPublicKeyBytes);
            return (KyberPublicKeyParameters)PqcPublicKeyFactory.CreateKey(x509certData);
        }
    }
}
