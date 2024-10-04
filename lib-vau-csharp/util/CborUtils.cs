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

using Newtonsoft.Json;
using PeterO.Cbor;
using System;

namespace lib_vau_csharp.util
{
    public static class CborUtils
    {
        public static byte[] EncodeToCbor(object objectToDecode)
        {
            string serializedObject = JsonConvert.SerializeObject(objectToDecode);
            return CBORObject.FromJSONString(serializedObject).EncodeToBytes();
        }

        public static byte[] DecodeByteValueFromCbor(CBORObject cborObject)
        {
            switch (cborObject.Type)
            {
                case CBORType.ByteString:
                    return cborObject.GetByteString();
                case CBORType.TextString:
                    return Convert.FromBase64String(cborObject.AsString());
                default:
                    throw new CBORException("CBOR Object was exptected to be bytes, but was neither encoded as a hex string or as Base64.");
            }
        }
    }
}
