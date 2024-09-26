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
    public class VauClientStateMachine : AbstractVauStateMachine
    {
        private VauMessage1 vauMessage1;
        private EccKyberKeyPair clientKeyPair1;
        private KdfKey1 kdfClientKey1;
        private KdfKey2 kdfClientKey2;
        private byte[] clientTranscript = new byte[0];
        private KEM kem = null;
        private KdfMessage clientKemResult1, clientKemResult2;
        private long requestCounter { get; set; } = 0;

        public override void initializeMachine(KEM k)
        {
            kem = k;

            clientKeyPair1 = EccKyberKeyPair.GenerateKeyPair(); // A_24428: 1/2. generate ECC-Keypair with Curve P-256 and Kyber768
            vauMessage1 = new VauMessage1(clientKeyPair1);
        }

        public byte[] generateMessage1()
        {
            this.clientTranscript = this.vauMessage1.toCBOR();  // A_24428: encode in CBOR
            return this.clientTranscript;
        }

        protected override byte GetRequestByte()
        {
            return 1;
        }

        protected override bool ValidateKeyId(byte[] keyId)
        {
            return Enumerable.SequenceEqual(kdfClientKey2.KeyId, keyId);
        }

        public byte[] receiveMessage2(byte[] message2Encoded)
        {
            VauMessage2 vauMessage2Client = VauMessage2.fromCbor(message2Encoded);
            clientTranscript = clientTranscript.Concat(message2Encoded).ToArray();

            DecapsulateMessage(vauMessage2Client); // A_24623: handle message 2
            VauPublicKeys transferredSignedServerPublicKeyList = DecryptAEAD(vauMessage2Client);
            byte[] aeadCiphertextMessage3 = EncapsulateMessage(transferredSignedServerPublicKeyList);

            kdfClientKey2 = this.clientKemResult1.getKDFKey2(this.clientKemResult2);
            this.encryptionVauKey = kdfClientKey2.ClientToServerAppData;
            this.decryptionVauKey = kdfClientKey2.ServerToClientAppData;
            KeyId = kdfClientKey2.KeyId;
            byte[] vauMessage3Encoded = createMessage3(aeadCiphertextMessage3);
            clientTranscript = clientTranscript.Concat(vauMessage3Encoded).ToArray();

            return vauMessage3Encoded;
        }

        private byte[] createMessage3(byte[] aeadCiphertextMessage3)
        {
            byte[] clientTranscriptToSend = clientTranscript.Concat(aeadCiphertextMessage3).ToArray();  // A_24623: concat the secrets   
            byte[] transcriptClientHash = DigestUtils.Sha256(clientTranscriptToSend);
            byte[] aeadCipherTextMessage3KeyKonfirmation = kem.EncryptAead(kdfClientKey2.ClientToServerKeyKonfirmation, transcriptClientHash);
            VauMessage3 vauMessage3 = new VauMessage3(aeadCiphertextMessage3, aeadCipherTextMessage3KeyKonfirmation);
            byte[] vauMessage3Encoded = CborUtils.EncodeToCbor(vauMessage3);
            return vauMessage3Encoded;
        }

        private byte[] EncapsulateMessage(VauPublicKeys transferredSignedServerPublicKeyList)
        {
            this.clientKemResult2 = KEM.EncapsulateMessage(transferredSignedServerPublicKeyList.EcdhPublicKey.ToEcPublicKey(), transferredSignedServerPublicKeyList.ToKyberPublicKey());
            VauMessage3InnerLayer vauMessage3InnerLayer = new VauMessage3InnerLayer(clientKemResult2.EcdhCt, clientKemResult2.KyberCt, false, false);

            byte[] message3InnerLayerEncoded = CborUtils.EncodeToCbor(vauMessage3InnerLayer);
            byte[] aeadCiphertextMessage3 = kem.EncryptAead(kdfClientKey1.ClientToServer, message3InnerLayerEncoded);
            return aeadCiphertextMessage3;
        }

        private void DecapsulateMessage(VauMessage2 vauMessage2Client)
        {
            this.clientKemResult1 = KEM.DecapsulateMessages(vauMessage2Client, clientKeyPair1); // A_24623: calculate secrets: ss_e_ecdh and ss_e_kyber768 
            kdfClientKey1 = clientKemResult1.getKDFKey1();  // A_24623: get ss_e
        }

        private VauPublicKeys DecryptAEAD(VauMessage2 vauMessage2Client)
        {
            byte[] transferredSignedServerPublicKey = kem.DecryptAead(kdfClientKey1.ServerToClient, vauMessage2Client.AeadCt);  // A_24623: decrypt AEAD_ct with K1_s2c
            SignedPublicVauKeys signedPublicVauKeysClient = SignedPublicVauKeys.fromCbor(transferredSignedServerPublicKey);     // A_24623:get signed public VAU-Keys

            VauPublicKeys transferredSignedServerPublicKeyList = signedPublicVauKeysClient.ExtractVauKeys();
            KeyUtils.CheckCertificateExpired(transferredSignedServerPublicKeyList.Exp);
            KeyUtils.VerifyClientMessageIsWellFormed(transferredSignedServerPublicKeyList.EcdhPublicKey, transferredSignedServerPublicKeyList);

            return transferredSignedServerPublicKeyList;
        }

        public void receiveMessage4(byte[] message4Encoded)
        {
            VauMessage4 vauMessage4Client = VauMessage4.fromCbor(message4Encoded);
            byte[] vauTranscript = kem.DecryptAead(kdfClientKey2.ServerToClientKeyKonfirmation, vauMessage4Client.AeadCtKeyKonfirmation);
            byte[] newClientTranscriptHash = DigestUtils.Sha256(clientTranscript);
            if (!Enumerable.SequenceEqual(vauTranscript, newClientTranscriptHash))
            {
                throw new InvalidKeyException("Vau transcript and new client transcript hash do not equal.");
            }
        }

        protected override void CheckRequestByte(byte requestByte)
        {
            if (requestByte != 2)
            {
                throw new InvalidOperationException("Request byte was unexpected. Expected 1, but got " + requestByte);
            }
        }

        protected override void CheckRequestCounter(long requestCounter)
        {
            if (this.requestCounter != requestCounter)
            {
                throw new ArgumentException($"Invalid request counter. Expected {(this.requestCounter + 1)}, got {requestCounter}.");
            }
        }
        protected override long GetRequestCounter()
        {
            return requestCounter;
        }
    }
}
