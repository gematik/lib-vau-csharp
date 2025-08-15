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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

namespace lib_vau_csharp.crypto
{
    public static class KyberCurve
    {
        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            KyberParameters kyberParameters = KyberParameters.kyber768;
            KyberKeyGenerationParameters kyberKeyParameters = new KyberKeyGenerationParameters(new SecureRandom(), kyberParameters);
            KyberKeyPairGenerator kpg = new KyberKeyPairGenerator();
            kpg.Init(kyberKeyParameters);
            return kpg.GenerateKeyPair();
        }

        public static SecretWithEncapsulationImpl pqcGenerateEncryptionKey(KyberPublicKeyParameters publicKey)
        {
            try
            {
                KyberKemGenerator kyberKemGenerator = new KyberKemGenerator(new SecureRandom());
                ISecretWithEncapsulation secretKeyWithEncapsulation = kyberKemGenerator.GenerateEncapsulated(publicKey);
                byte[] ct = secretKeyWithEncapsulation.GetEncapsulation();
                byte[] sharedSecret = secretKeyWithEncapsulation.GetSecret();

                byte[] resultSecret = UsingLastOfficialKyberSpecification(sharedSecret, ct);

                return new SecretWithEncapsulationImpl(resultSecret, ct);
            }
            catch (Exception e)
            {
                throw new KyberException("Could not generate Kyber encryption key from public key", e);
            }
        }

        public static byte[] pqcGenerateEncryptionKey(KyberPrivateKeyParameters privateKey, byte[] ct)
        {
            try
            {
                KyberKemExtractor kyberKemExtractor = new KyberKemExtractor(privateKey);
                byte[] sharedSecret = kyberKemExtractor.ExtractSecret(ct);
                return UsingLastOfficialKyberSpecification(sharedSecret, ct);
            }
            catch (Exception e)
            {
                throw new KyberException("Could not generate Kyber encryption key from private key", e);
            }
        }

        // This trick is necessary since BouncyCastle does not implement Kyber versio 3.0.2, but rather the current draft
        // The trick is derived from https://words.filippo.io/dispatches/mlkem768/#bonus-track-using-a-ml-kem-implementation-as-kyber-v3
        private static byte[] UsingLastOfficialKyberSpecification(byte[] sharedSecret, byte[] ct)
        {
            return Arrays.CopyOfRange(Shake256(Arrays.Concatenate(sharedSecret, Sha3_256(ct))), 0, 32);
        }

        private static byte[] Shake256(byte[] input)
        {
            byte[] result = new byte[64];
            ShakeDigest digest = new ShakeDigest(256);
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(result, 0);
            return result;
        }

        private static byte[] Sha3_256(byte[] input)
        {
            byte[] result = new byte[32];
            Sha3Digest digest = new Sha3Digest(256);
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(result, 0);
            return result;
        }
    }
}
