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
using lib_vau_csharp.data;
using lib_vau_csharp.util;
using Org.BouncyCastle.Security;
using System;
using System.Linq;

namespace lib_vau_csharp
{
    public class VauServerStateMachine : AbstractVauStateMachine
    {
        private readonly SignedPublicVauKeys signedPublicVauKeys;
        private readonly EccKyberKeyPair serverVauKeys;
        private byte[] c2s; //S_K1_c2s
        private byte[] s2c; //S_K1_s2c
        private KdfMessage kemResult1;
        private KdfMessage kemResult2;
        private byte[] serverTranscript;
        private KdfKey2 serverKey2;
        private static readonly int ExpirationDays = 30;
        private KEM kem = null;
        private long clientRequestCounter { get; set; }

        protected override byte GetRequestByte()
        {
            return 2;
        }

        protected override void CheckRequestCounter(long requestCounter)
        {
            clientRequestCounter = requestCounter;
        }

        protected override bool ValidateKeyId(byte[] keyId)
        {
            return Enumerable.SequenceEqual(serverKey2.KeyId, keyId);
        }

        protected override long GetRequestCounter()
        {
            return clientRequestCounter;
        }

        protected override void CheckRequestByte(byte requestByte)
        {
            if (requestByte != 1)
            {
                throw new InvalidOperationException("Request byte was unexpected. Expected 1, but got " + requestByte);
            }
        }

        public VauServerStateMachine(SignedPublicVauKeys signedPublicVauKeys, EccKyberKeyPair serverVauKeys) : base()
        {
            int iat = signedPublicVauKeys.ExtractVauKeys().Iat;
            int exp = signedPublicVauKeys.ExtractVauKeys().Exp;
            if (exp - iat > ExpirationDays * 60 * 60 * 24)
            {
                throw new ArgumentException("Dates of initialization and expiration of server keys can be only up to 30 days apart.");
            }

            this.signedPublicVauKeys = signedPublicVauKeys;
            this.serverVauKeys = serverVauKeys;
        }

        public override void initializeMachine(KEM k)
        {
            kem = k;
        }

        public byte[] receiveMessage1(byte[] message1Encoded)
        {
            KeyUtils.CheckCertificateExpired(signedPublicVauKeys.ExtractVauKeys().Exp);

            VauMessage1 vauMessage1 = VauMessage1.fromCbor(message1Encoded);
            serverTranscript = message1Encoded;

            byte[] aeadCiphertextMessage2 = EncapsulateMessage(vauMessage1);
            return generateMessage2(aeadCiphertextMessage2);
        }

        public byte[] generateMessage2(byte[] aeadCiphertextMessage2)
        {
            VauMessage2 vauMessage2 = new VauMessage2(kemResult1.EcdhCt, kemResult1.KyberCt, aeadCiphertextMessage2);
            byte[] message2Encoded = CborUtils.EncodeToCbor(vauMessage2);
            serverTranscript = serverTranscript.Concat(message2Encoded).ToArray();
            return message2Encoded;
        }

        private byte[] EncapsulateMessage(VauMessage1 vauMessage1)
        {
            kemResult1 = KEM.EncapsulateMessage(vauMessage1.EcdhPublicKey.ToEcPublicKey(), vauMessage1.ToKyberPublicKey());
            KdfKey1 serverKey1 = kemResult1.getKDFKey1();
            c2s = serverKey1.ClientToServer;
            s2c = serverKey1.ServerToClient;
            byte[] encodedSignedPublicVauKeys = CborUtils.EncodeToCbor(signedPublicVauKeys);
            byte[] aeadCiphertextMessage2 = kem.EncryptAead(s2c, encodedSignedPublicVauKeys);
            return aeadCiphertextMessage2;
        }

        private void DecapsulateMessage(VauMessage3 vauMessage3Server)
        {
            byte[] kemCertificatesEncoded = kem.DecryptAead(c2s, vauMessage3Server.AeadCt);
            VauMessage3InnerLayer kemCertificates = VauMessage3InnerLayer.fromCbor(kemCertificatesEncoded);
            kemResult2 = KEM.DecapsulateMessages(kemCertificates, serverVauKeys);
            serverKey2 = kemResult1.getKDFKey2(kemResult2);
            this.encryptionVauKey = serverKey2.ServerToClientAppData;
            this.decryptionVauKey = serverKey2.ClientToServerAppData;
            KeyId = serverKey2.KeyId;
        }

        public byte[] receiveMessage3(byte[] message3Encoded)
        {
            KeyUtils.CheckCertificateExpired(signedPublicVauKeys.ExtractVauKeys().Exp);
            VauMessage3 vauMessage3Server = VauMessage3.fromCbor(message3Encoded);
            byte[] serverTranscriptToCheck = serverTranscript.Concat(vauMessage3Server.AeadCt).ToArray();
            serverTranscript = serverTranscript.Concat(message3Encoded).ToArray();

            DecapsulateMessage(vauMessage3Server);
            return createMessage4(vauMessage3Server, serverTranscriptToCheck);
        }

        public byte[] createMessage4(VauMessage3 vauMessage3Server, byte[] serverTranscriptToCheck)
        {
            byte[] clientTransciptHash = kem.DecryptAead(serverKey2.ClientToServerKeyKonfirmation, vauMessage3Server.AeadCtKeyKonfirmation);
            byte[] clientVauHashCalculation = DigestUtils.Sha256(serverTranscriptToCheck);
            if (!Enumerable.SequenceEqual(clientTransciptHash, clientVauHashCalculation))
            {
                throw new InvalidKeyException("Client transcript hash and vau calculation do not equal.");
            }
            byte[] serverTranscriptHash = DigestUtils.Sha256(serverTranscript);
            byte[] aeadCipherTextMessage4KeyKonfirmation = kem.EncryptAead(serverKey2.ServerToClientKeyKonfirmation, serverTranscriptHash);
            VauMessage4 vauMessage4 = new VauMessage4(aeadCipherTextMessage4KeyKonfirmation);
            byte[] vauMessage4Encoded = CborUtils.EncodeToCbor(vauMessage4);
            return vauMessage4Encoded;
        }
    }
}
