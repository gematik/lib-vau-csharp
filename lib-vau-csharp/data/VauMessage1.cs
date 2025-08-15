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

using lib_vau_csharp.util;
using Newtonsoft.Json;
using PeterO.Cbor;
using System;

namespace lib_vau_csharp.data
{
    public class VauMessage1 : VauBasicPublicKey
    {
        private const string _messageType = "M1";
        [JsonProperty(nameof(MessageType))]
        public static string MessageType => _messageType;

        public VauMessage1(EccKyberKeyPair clientKey1) : base(clientKey1)
        {
        }

        public VauMessage1(VauEccPublicKey ecdhPublicKey, byte[] kyberPublicKey) : base(ecdhPublicKey, kyberPublicKey)
        {
        }

        public static CBORObject toCBOR(VauMessage1 message1)
        {
            return CBORObject.NewMap()
                .Add("MessageType", MessageType)
                .Add("ECDH_PK", VauEccPublicKey.toCBOR(message1.EcdhPublicKey))
                .Add("Kyber768_PK", message1.KyberPublicKeyBytes);
        }

        public static VauMessage1 fromCbor(byte[] encodedObject)
        {
            try
            {
                CBORObject cborObject = CBORObject.DecodeFromBytes(encodedObject);
                if (cborObject["MessageType"].AsString() != _messageType)
                {
                    throw new CBORException("This CBor object is not a VauMessage1 object!");
                }

                VauMessage1 vauMessage1 = new VauMessage1(
                    VauEccPublicKey.fromCbor(cborObject["ECDH_PK"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["Kyber768_PK"]));
                return vauMessage1;
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to VauMessage1.", e.InnerException);
            }
        }
    }
}
