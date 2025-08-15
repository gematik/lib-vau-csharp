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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace lib_vau_csharp.crypto
{
    public class AesGcm
    {
        private readonly IBufferedCipher m_encCipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        private readonly IBufferedCipher m_decCipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");

        public byte[] ivValue { get; set; }

        public void initAESForEncryption(byte[] random,
            long lCounter,
            byte[] assocData,
            byte[] key)
        {
            // True Random value must be a minimum of 4 bytes
            if (random == null || random.Length < 4)
            {
                throw new ArgumentNullException(nameof(random), "Invalid random value!");
            }

            // A_24628 -> 32 Byte KeyID aus dem Handshake
            if (key == null || key.Length != 32)
            {
                throw new ArgumentNullException(nameof(key), "Invalid key value!");
            }

            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("AES", key);
            ivValue = initializeIV(random, lCounter);
            var aes_parameters = new AeadParameters(keyParam, 128, ivValue, assocData);
            m_encCipher.Init(true, aes_parameters);
            m_decCipher.Init(false, aes_parameters);
        }

        public void initAESForDecryption(byte[] iv,
            byte[] assocData,
            byte[] key)
        {
            // True Random value must be a minimum of 4 bytes
            if (iv == null || iv.Length < 4)
            {
                throw new ArgumentNullException(nameof(iv), "Invalid iv value!");
            }

            // A_24628 -> 32 Byte KeyID aus dem Handshake
            if (key == null || key.Length != 32)
            {
                throw new ArgumentNullException(nameof(key), "Invalid key value!");
            }

            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("AES", key);
            ivValue = iv;
            var aes_parameters = new AeadParameters(keyParam, 128, ivValue, assocData);
            m_encCipher.Init(true, aes_parameters);
            m_decCipher.Init(false, aes_parameters);
        }
    
        private static byte[] initializeIV(byte[] random, long lCounter)
        {
            // A_24628 -> 32 Bit Random + 64 Bit Verschlüsselungszähler
            if (random?.Length != 4)
            {
                throw new ArgumentNullException(nameof(random), "Invalid random value!");
            }

            byte[] counter = BitConverter.GetBytes(lCounter).Reverse().ToArray();   // A_24629, A_24631 -> 64 Bit encryption counter
            return random.Concat(counter).ToArray();                                // A_24628 -> concat random and counter
        }        

        public byte[] encryptData(byte[] clearText)
        {
            _ = clearText ?? throw new ArgumentNullException(nameof(clearText), "No valid data for encryption!");

            return m_encCipher.DoFinal(clearText);
        }

        public byte[] decryptData(byte[] encText)
        {
            _ = encText ?? throw new ArgumentNullException(nameof(encText), "No valid encryption text!");

            return m_decCipher.DoFinal(encText);
        }
    }
}
