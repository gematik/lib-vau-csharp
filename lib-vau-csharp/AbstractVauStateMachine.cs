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

using lib_vau_csharp.crypto;
using lib_vau_csharp.exceptions;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Linq;

namespace lib_vau_csharp
{
    public abstract class AbstractVauStateMachine
    {
        private static int MinimumCiphertextLength = 1 + 1 + 1 + 8 + 32 + 12 + 1 + 16; //A_24628

        protected abstract byte GetRequestByte();

        protected abstract long GetRequestCounter();

        protected abstract void CheckRequestCounter(long requestCounter);

        protected abstract void CheckRequestByte(byte requestByte);


        public byte[] KeyId { get; protected set; }
        protected byte[] encryptionVauKey { get; set; }
        protected byte[] decryptionVauKey { get; set; }
        private bool isPu { get; set; } = false;
        protected abstract bool ValidateKeyId(byte[] keyId);

        public virtual byte[] EncryptVauMessage(byte[] plaintext)
        {
            byte versionByte = 2;
            byte puByte = 0;
            byte requestByte = GetRequestByte();
            byte[] requestCounterBytes = BitConverter.GetBytes(GetRequestCounter()).Reverse().ToArray();
            byte[][] headerBytes = new byte[][] { new byte[] { versionByte }, new byte[] { puByte }, new byte[] { requestByte }, requestCounterBytes, KeyId };
            byte[] header = Arrays.ConcatenateAll(headerBytes);

            byte[] random = new byte[4];
            new SecureRandom().NextBytes(random);

            AesGcm aesGcm = new AesGcm();
            aesGcm.initAESForEncryption(random, GetRequestCounter(), header, encryptionVauKey);
            byte[] ciphertext = aesGcm.encryptData(plaintext);
            byte[][] concatBytes = new byte[][] { header, aesGcm.ivValue, ciphertext };
            byte[] bytes = Arrays.ConcatenateAll(concatBytes);
            return bytes;
        }

        public byte[] DecryptVauMessage(byte[] ciphertext)
        {
            if (ciphertext.Length < MinimumCiphertextLength)
            {
                throw new ArgumentException(
                  "Invalid ciphertext length. Needs to be at least " + MinimumCiphertextLength + " bytes.");
            }

            byte[] header = new byte[43];
            Array.Copy(ciphertext, header, 43);
            byte versionByte = header[0];
            if (versionByte != 2)
            {
                throw new ArgumentException("Invalid version byte. Expected 2, got " + versionByte);
            }
            byte puByte = header[1];
            if (puByte != (byte)(isPu ? 1 : 0))
            {
                throw new ArgumentException($"Invalid PU byte. Expected {(isPu ? 1 : 0)}, got {puByte}.");
            }
            byte requestByte = header[2];
            CheckRequestByte(requestByte);
            long receivedRequestCounter = BitConverter.ToInt64(header.Skip(3).Take(8).Reverse().ToArray(), 0);
            CheckRequestCounter(receivedRequestCounter);
            byte[] headerKeyId = new byte[header.Length - 11];
            Array.Copy(header, 11, headerKeyId, 0, headerKeyId.Length);
            if (!ValidateKeyId(headerKeyId))
            {
                throw new ArgumentException("Key ID in the header is not correct");
            }
            byte[] iv = new byte[12];
            Array.Copy(ciphertext, 43, iv, 0, iv.Length);
            byte[] ct = new byte[ciphertext.Length - 55];
            Array.Copy(ciphertext, 55, ct, 0, ct.Length);
            try
            {
                AesGcm aesGcm = new AesGcm();
                aesGcm.initAESForDecryption(iv, header, decryptionVauKey);
                return aesGcm.decryptData(ct);
            }
            catch (Exception e)
            {
                throw new VauDecryptionException("Exception thrown whilst trying to decrypt VAU message: " + e.Message, e);
            }
        }
    }
}
//sehr viel Magic Numbers, Vorschlag als const Wert mit sprechenden Namen deklarieren
