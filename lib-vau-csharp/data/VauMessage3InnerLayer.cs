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
    public class VauMessage3InnerLayer
    {
        [JsonProperty("ECDH_ct")]
        public VauEccPublicKey EcdhCt { get; private set; }
        [JsonProperty("Kyber768_ct")]
        public byte[] KyberCt { get; private set; }
        [JsonProperty("ERP")]
        public bool Erp { get; private set; }
        [JsonProperty("ESO")]
        public bool Eso { get; private set; }

        [JsonConstructor]
        public VauMessage3InnerLayer([JsonProperty("ECDH_ct")] VauEccPublicKey ecdhCt, [JsonProperty("Kyber768_ct")] byte[] kyberCt, [JsonProperty("ERP")] bool erp, [JsonProperty("ESO")] bool eso)
        {
            EcdhCt = ecdhCt;
            KyberCt = kyberCt;
            Erp = erp;
            Eso = eso;
        }

        public byte[] toCbor() {
          CBORObject cborVauKey = CBORObject.NewOrderedMap();
          cborVauKey.Add("ECDH_ct", EcdhCt);
          cborVauKey.Add("Kyber768_ct", KyberCt);
          cborVauKey.Add("ERP",  Erp);
          cborVauKey.Add("ESO",  Eso);

          return cborVauKey.EncodeToBytes();
        }

        public static VauMessage3InnerLayer fromCbor(byte[] encodedObject)
        {
            try
            {
                CBORObject cborObject = CBORObject.DecodeFromBytes(encodedObject);
                return new VauMessage3InnerLayer(
                    VauEccPublicKey.fromCbor(cborObject["ECDH_ct"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["Kyber768_ct"]),
                    cborObject["ERP"].AsBoolean(),
                    cborObject["ESO"].AsBoolean());
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to VauMessage3InnerLayer.", e.InnerException);
            }
        }
    }
}
