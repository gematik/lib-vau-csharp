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

using lib_vau_csharp.exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using System;

namespace lib_vau_csharp.crypto
{
    public static class KyberCurve
    {
        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            MLKemParameters kyberParameters = MLKemParameters.ml_kem_768;
            MLKemKeyGenerationParameters kyberKeyParameters = new MLKemKeyGenerationParameters(new SecureRandom(), kyberParameters);
            MLKemKeyPairGenerator kpg = new MLKemKeyPairGenerator();
            kpg.Init(kyberKeyParameters);
            return kpg.GenerateKeyPair();
        }

        public static SecretWithEncapsulationImpl pqcGenerateEncryptionKey(MLKemPublicKeyParameters publicKey)
        {
            try
            {
                MLKemEncapsulator mLKemEncapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
                mLKemEncapsulator.Init(publicKey);

                var encapsulated = new byte[mLKemEncapsulator.EncapsulationLength];
                var secret = new byte[mLKemEncapsulator.SecretLength];
                mLKemEncapsulator.Encapsulate(encapsulated, 0, encapsulated.Length, secret, 0, secret.Length);
                return new SecretWithEncapsulationImpl(secret, encapsulated);
            }
            catch (Exception e)
            {
                throw new KyberException("Could not generate Kyber encryption key from public key", e);
            }
        }

        public static byte[] pqcGenerateEncryptionKey(MLKemPrivateKeyParameters privateKey, byte[] ct)
        {
            try
            {
                MLKemDecapsulator mLKemDecapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
                mLKemDecapsulator.Init(privateKey);
                byte[] sharedSecret = new byte[mLKemDecapsulator.SecretLength];
                mLKemDecapsulator.Decapsulate(ct, 0, ct.Length, sharedSecret, 0, sharedSecret.Length);
                return sharedSecret;
            }
            catch (Exception e)
            {
                throw new KyberException("Could not generate Kyber encryption key from private key", e);
            }
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
