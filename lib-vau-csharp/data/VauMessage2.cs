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

using lib_vau_csharp.util;
using Newtonsoft.Json;
using PeterO.Cbor;
using System;

namespace lib_vau_csharp.data
{
    public class VauMessage2
    {
        private const string _messageType = "M2";
        public string MessageType => _messageType;
        public VauEccPublicKey EcdhCt { get; private set; }
        public byte[] KyberCt { get; private set; }
        public byte[] AeadCt { get; private set; }

        public VauMessage2(VauEccPublicKey ecdhCt, byte[] kyberCt, byte[] aeadCt)
        {
            this.EcdhCt = ecdhCt;
            this.KyberCt = kyberCt;
            this.AeadCt = aeadCt;
        }

        public static CBORObject toCBOR(VauMessage2 message2 )
        {
            return CBORObject.NewMap()
                .Add("MessageType", message2.MessageType)
                .Add("ECDH_ct", VauEccPublicKey.toCBOR(message2.EcdhCt))
                .Add("Kyber768_ct", message2.KyberCt)
                .Add("AEAD_ct", message2.AeadCt);
        }

        public static VauMessage2 fromCbor(byte[] encodedObject)
        {
            try
            {
                CBORObject cborObject = CBORObject.DecodeFromBytes(encodedObject);
                if (cborObject["MessageType"].AsString() != _messageType)
                {
                    throw new CBORException("This CBor object is not a VauMessage2 object!");
                }

                VauMessage2 vauMessage2 = new VauMessage2(
                    VauEccPublicKey.fromCbor(cborObject["ECDH_ct"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["Kyber768_ct"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["AEAD_ct"]));
                return vauMessage2;
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to VauMessage2.", e.InnerException);
            }
        }
    }
}
