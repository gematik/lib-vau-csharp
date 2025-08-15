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

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using System.Collections.Generic;

namespace lib_vau_csharp.data
{
    public class KdfMessage
    {
        public VauEccPublicKey EcdhCt { get; private set; }
        public ECPrivateKeyParameters EcdhPrivateKey { get; private set; } //only for development!
        public byte[] EcdhSharedSecret { get; private set; }
        public byte[] KyberCt { get; private set; }
        public byte[] KyberSharedSecret { get; private set; }

        public KdfMessage(VauEccPublicKey ecdhCt, byte[] ecdhSharedSecret, byte[] kyberCt, byte[] kyberSharedSecret)
        {
            this.EcdhCt = ecdhCt;
            this.EcdhPrivateKey = null;
            this.EcdhSharedSecret = ecdhSharedSecret;
            this.KyberCt = kyberCt;
            this.KyberSharedSecret = kyberSharedSecret;
        }


        internal KdfMessage(VauEccPublicKey ecdhCt, ECPrivateKeyParameters ecdhPrivateKey, byte[] ecdhSharedSecret, byte[] kyberCt, byte[] kyberSharedSecret)
        {
            this.EcdhCt = ecdhCt;
            this.EcdhPrivateKey = ecdhPrivateKey;
            this.EcdhSharedSecret = ecdhSharedSecret;
            this.KyberCt = kyberCt;
            this.KyberSharedSecret = kyberSharedSecret;
        }

        public KdfKey1 getKDFKey1()
        {
            List<byte[]> byteArrays = DeriveKey(Arrays.Concatenate(this.EcdhSharedSecret, this.KyberSharedSecret), 2);  // A_24623: concat secrets ss_e_ecdh and ss_e_kyber768 to ss_e
            return new KdfKey1(byteArrays[0], byteArrays[1]);   // A_24623: create K1_c2s and K1_s2c
        }

        public KdfKey2 getKDFKey2(KdfMessage message2)
        {
            List<byte[]> byteArrays = DeriveKey(Arrays.ConcatenateAll(this.EcdhSharedSecret, this.KyberSharedSecret, message2.EcdhSharedSecret, message2.KyberSharedSecret), 5);
            return new KdfKey2(byteArrays[0], byteArrays[1], byteArrays[2], byteArrays[3], byteArrays[4]);
        }

        public static List<byte[]> DeriveKey(byte[] sharedSecret, int numSegments)
        {
            List<byte[]> encodedKeys = new List<byte[]>();
            const int sequenceLength = 32;
            Sha256Digest sha256Digest = new Sha256Digest();
            HkdfBytesGenerator hkdfBytesGenerator = new HkdfBytesGenerator(sha256Digest);
            hkdfBytesGenerator.Init(new HkdfParameters(sharedSecret, null, null));
            byte[] outBytes = new byte[numSegments * sequenceLength];
            hkdfBytesGenerator.GenerateBytes(outBytes, 0, outBytes.Length);
            for (int i = 0; i < numSegments; i++)
            {
                byte[] newEntry = Arrays.CopyOfRange(outBytes, i * sequenceLength, (i + 1) * sequenceLength);
                encodedKeys.Add(newEntry);
            }
            return encodedKeys;
        }
    }
}
