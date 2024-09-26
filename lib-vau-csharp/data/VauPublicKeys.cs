﻿/*
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
    public class VauPublicKeys : VauBasicPublicKey
    {
        [JsonProperty("iat")]
        public int Iat { get; private set; }
        [JsonProperty("exp")]
        public int Exp { get; private set; }
        [JsonProperty("comment")]
        public string Comment { get; private set; }

        public VauPublicKeys(EccKyberKeyPair eccKyberKeyPair, string comment, TimeSpan validity) : base(eccKyberKeyPair)
        {
            Iat = (int)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Exp = Iat + (int)validity.TotalSeconds;
            Comment = comment;
        }

        [JsonConstructor]
        public VauPublicKeys([JsonProperty("ECDH_PK")] VauEccPublicKey ecdhPublicKey, [JsonProperty("Kyber768_PK")] byte[] kyberPublicKeyBytes, [JsonProperty("comment")] string comment, [JsonProperty("iat")] int iat, [JsonProperty("exp")] int exp) : base(ecdhPublicKey, kyberPublicKeyBytes)
        {
            Iat = iat;
            Exp = exp;
            Comment = comment;
        }

        public static VauPublicKeys fromCbor(byte[] encodedObject)
        {
            try
            {
                CBORObject cborObject = CBORObject.DecodeFromBytes(encodedObject);
                VauPublicKeys vauPublicKeys = new VauPublicKeys(
                    VauEccPublicKey.fromCbor(cborObject["ECDH_PK"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["Kyber768_PK"]),
                    cborObject["comment"].AsString(),
                    cborObject["iat"].AsInt32(),
                    cborObject["exp"].AsInt32());
                return vauPublicKeys;
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to VauPublicKeys.", e.InnerException);
            }
        }
    }
}