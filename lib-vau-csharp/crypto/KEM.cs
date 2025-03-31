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
using lib_vau_csharp.exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Linq;

namespace lib_vau_csharp.crypto
{
    public class KEM
    {
        private const int GcmIvLength = 12;
        private GcmBlockCipher gcmCipher = null;
        private int keySize = 0;

        public const int KEYSIZE_256 = 32;

        public enum KEMEngines
        {
            AesEngine = 0,
            AesLightEngine = 1
        }

        public static KEM initializeKEM(KEMEngines ke, int keysize)
        {
            KEM kem = new KEM();
            switch (ke)
            {
                case KEMEngines.AesEngine:
                    kem.gcmCipher = new GcmBlockCipher(new AesEngine());
                    break;
                case KEMEngines.AesLightEngine:
                    kem.gcmCipher = new GcmBlockCipher(new AesLightEngine());
                    break;
                default:
                    throw new KemException("no valid Engine for GcmBlockCipher selected!");
            }

            if (keysize != KEYSIZE_256)
            {
                throw new KemException("Key size must be 32 byte!");
            }
            kem.keySize = keysize;
            return kem;
        }

        private KEM()
        {
        }

        private AeadParameters initAeadParameter(byte[] key, byte[] iv)
        {
            if (key.Length != keySize)
            {
                throw new KemException($"key size must be {keySize} byte but is {key.Length}!");
            }
            KeyParameter keyParameter = new KeyParameter(key);
            return new AeadParameters(keyParameter, gcmCipher.GetBlockSize() * 8, iv);
        }

        private byte[] initGCMCipherForEncryption(byte[] key)
        {
            byte[] iv = new byte[GcmIvLength];
            new SecureRandom().NextBytes(iv);

            AeadParameters aeadParameters = initAeadParameter(key, iv);
            gcmCipher.Init(true, aeadParameters);
            return iv;
        }

        private byte[] initGCMCipherForDecryption(byte[] key, byte[] cipherText)
        {
            byte[] iv = Arrays.CopyOfRange(cipherText, 0, GcmIvLength);
            byte[] ct = Arrays.CopyOfRange(cipherText, GcmIvLength, cipherText.Length);

            AeadParameters aeadParameters = initAeadParameter(key, iv);
            gcmCipher.Init(false, aeadParameters);
            return ct;
        }

        public static KdfMessage EncapsulateMessage(ECPublicKeyParameters remoteEcdhPublicKey, MLKemPublicKeyParameters kyberPublicKey)
        {
            EllipticCurve ecCurve = EllipticCurve.GenerateEllipticCurve(EllipticCurve.SECP256R1);
            AsymmetricCipherKeyPair temporaryEcdhKeyPair = ecCurve.GenerateKeyPair();
            byte[] ecdhSharedSecret = ecCurve.GetSharedSecret(remoteEcdhPublicKey, (ECPrivateKeyParameters)temporaryEcdhKeyPair.Private);
            SecretWithEncapsulationImpl secretWithEncapsulation = KyberCurve.pqcGenerateEncryptionKey(kyberPublicKey);
            return new KdfMessage(
                new VauEccPublicKey((ECPublicKeyParameters)temporaryEcdhKeyPair.Public),
                (ECPrivateKeyParameters)temporaryEcdhKeyPair.Private,
                ecdhSharedSecret,
                secretWithEncapsulation.GetEncapsulation(),
                secretWithEncapsulation.GetSecret());
        }

        public static KdfMessage DecapsulateMessages(VauMessage2 ciphertext, EccKyberKeyPair privateKeys)
        {
            ECPublicKeyParameters ecdhPublicKeySender = ciphertext.EcdhCt.ToEcPublicKey();          // A_24623: get EC public Key
            EllipticCurve ecCurve = EllipticCurve.GenerateEllipticCurve(EllipticCurve.SECP256R1);
            byte[] ecdhSharedSecret = ecCurve.GetSharedSecret(ecdhPublicKeySender, (ECPrivateKeyParameters)privateKeys.EcdhKeyPair.Private); //  A_24623: calculate secret: ss_e_ecdh with ec keypair
            byte[] sharedSecretClient = KyberCurve.pqcGenerateEncryptionKey((MLKemPrivateKeyParameters)privateKeys.KyberKeyPair.Private, ciphertext.KyberCt);  //  A_24623: calculate secret: ss_e_kyber768 with kyber keypair
            return new KdfMessage(null, ecdhSharedSecret, null, sharedSecretClient);
        }

        public static KdfMessage DecapsulateMessages(VauMessage3InnerLayer ciphertext, EccKyberKeyPair privateKeys)
        {
            EllipticCurve ecCurve = EllipticCurve.GenerateEllipticCurve(EllipticCurve.SECP256R1);
            ECPublicKeyParameters ecdhPublicKeySender = ciphertext.EcdhCt.ToEcPublicKey();
            byte[] ecdhSharedSecret = ecCurve.GetSharedSecret(ecdhPublicKeySender, (ECPrivateKeyParameters)privateKeys.EcdhKeyPair.Private);
            byte[] sharedSecretClient = KyberCurve.pqcGenerateEncryptionKey((MLKemPrivateKeyParameters)privateKeys.KyberKeyPair.Private, ciphertext.KyberCt);
            return new KdfMessage(null, ecdhSharedSecret, null, sharedSecretClient);
        }

        public byte[] EncryptAead(byte[] key, byte[] plaintext)
        {
            byte[] iv = initGCMCipherForEncryption(key);
            byte[] ciphertext = new byte[gcmCipher.GetOutputSize(plaintext.Length)];
            int length = gcmCipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            gcmCipher.DoFinal(ciphertext, length);
            return iv.Concat(ciphertext).ToArray();
        }

        public byte[] DecryptAead(byte[] key, byte[] ciphertext)
        {
            byte[] ct = initGCMCipherForDecryption(key, ciphertext);
            byte[] plaintext = new byte[gcmCipher.GetOutputSize(ct.Length)];
            int length = gcmCipher.ProcessBytes(ct, 0, ct.Length, plaintext, 0);
            gcmCipher.DoFinal(plaintext, length);
            return plaintext;
        }
    }
}
