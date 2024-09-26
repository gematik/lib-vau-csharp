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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Linq;

namespace lib_vau_csharp.crypto
{
    public class AesGcm
    {
        private readonly IBufferedCipher m_encCipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        private readonly IBufferedCipher m_decCipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");

        public AesGcm(
            byte[] iv,
            byte[] assocData,
            byte[] key
        )
        {
            // A_24628 -> 32 Byte KeyID aus dem Handshake
            if (key?.Length != 32)
            {
                throw new ArgumentNullException(nameof(key), "Invalid key value!");
            }

            // A_24628 -> 32 Bit Zufall + 64 Bit Verschlüsselungszähler
            if (iv?.Length != 12)
            {
                throw new ArgumentNullException(nameof(iv), "Invalid iv value!");
            }

            initializeAes(iv, assocData, key);
        }

        private void initializeAes(byte[] iv, byte[] assocData, byte[] key)
        {
            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("AES", key);
            var nonce = initializeIV(iv.Take(iv.Length - 8).ToArray(), 1);
            var aes_parameters = new AeadParameters(keyParam, 128, nonce, assocData);
            m_encCipher.Init(true, aes_parameters);
            m_decCipher.Init(false, aes_parameters);
        }

        private static byte[] initializeIV(byte[] random, long lCounter)
        {
            // A_24628 -> Random value must be 32 bit value
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
