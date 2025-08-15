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
    public class VauMessage4
    {
        private const string _messageType = "M4";
        public static string MessageType => _messageType;
        public byte[] AeadCtKeyKonfirmation { get; private set; }

        public VauMessage4([JsonProperty("AEAD_ct_key_confirmation")] byte[] aeadCtKeyKonfirmation)
        {
            AeadCtKeyKonfirmation = aeadCtKeyKonfirmation;
        }

        public static CBORObject toCBOR(VauMessage4 message4)
        {
            return CBORObject.NewMap()
                .Add("MessageType", MessageType)
                .Add("AEAD_ct_key_confirmation", message4.AeadCtKeyKonfirmation);
        }

        public static VauMessage4 fromCbor(byte[] encodedObject)
        {
            try
            {
                CBORObject cborObject = CBORObject.DecodeFromBytes(encodedObject);
                if (cborObject["MessageType"].AsString() != _messageType)
                {
                    throw new CBORException("This CBor object is not a VauMessage4 object!");
                }
                VauMessage4 vauMessage4 = new VauMessage4(
                    CborUtils.DecodeByteValueFromCbor(cborObject["AEAD_ct_key_confirmation"]));
                return vauMessage4;
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to VauMessage4.", e.InnerException);
            }
        }
    }
}
