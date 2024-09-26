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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using PeterO.Cbor;
using System;
using System.Security.Cryptography;

namespace lib_vau_csharp.data
{
    public class SignedPublicVauKeys
    {
        [JsonProperty("signed_pub_keys")]
        byte[] SignedPublicKeys;
        [JsonProperty("signature-ES256")]
        byte[] SignatureEs256;
        [JsonProperty("cert_hash")]
        byte[] CertHash;
        [JsonProperty("cdv")]
        int Cdv;
        [JsonProperty("ocsp_response")]
        byte[] OcspResponse;

        const string DIGESTSIGNER = "SHA-256withECDSA";

        [JsonConstructor]
        public SignedPublicVauKeys([JsonProperty("signed_pub_keys")] byte[] signedPublicKeys, [JsonProperty("signature-ES256")] byte[] signatureEs256, [JsonProperty("cert_hash")] byte[] certHash, [JsonProperty("cdv")] int cdv, [JsonProperty("ocsp_response")] byte[] ocspResponse)
        {
            SignedPublicKeys = signedPublicKeys;
            SignatureEs256 = signatureEs256;
            CertHash = certHash;
            Cdv = cdv;
            OcspResponse = ocspResponse;
        }

        public static SignedPublicVauKeys Sign(byte[] serverAutCertificate, ECPrivateKeyParameters eCPrivateKeyParameters, byte[] ocspResponseAutCertificate, int cdv, VauPublicKeys vauServerKeys)
        {
            byte[] encodedServerKeys = CborUtils.EncodeToCbor(vauServerKeys);

            return new SignedPublicVauKeys(
                encodedServerKeys,
                GenerateEccSignature(encodedServerKeys, eCPrivateKeyParameters),
                SHA256.Create().ComputeHash(serverAutCertificate),
                cdv,
                ocspResponseAutCertificate
                );
        }

        private static byte[] GenerateEccSignature(byte[] tbsData, ECPrivateKeyParameters privateKey)
        {
            DsaDigestSigner verifier = (DsaDigestSigner)SignerUtilities.GetSigner(DIGESTSIGNER);
            verifier.Init(true, privateKey);
            verifier.BlockUpdate(tbsData, 0, tbsData.Length);
            byte[] sig = verifier.GenerateSignature();
            return sig;
        }

        public VauPublicKeys ExtractVauKeys()
        {
            return VauPublicKeys.fromCbor(SignedPublicKeys);
        }

        public static SignedPublicVauKeys fromCbor(byte[] encodedObject)
        {
            try
            {
                CBORObject cborObject = CBORObject.DecodeFromBytes(encodedObject);
                SignedPublicVauKeys signedPublicVauKeys = new SignedPublicVauKeys(
                    CborUtils.DecodeByteValueFromCbor(cborObject["signed_pub_keys"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["signature-ES256"]),
                    CborUtils.DecodeByteValueFromCbor(cborObject["cert_hash"]),
                    cborObject["cdv"].AsInt32(),
                    CborUtils.DecodeByteValueFromCbor(cborObject["ocsp_response"]));
                return signedPublicVauKeys;
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to SignedPublicVauKeys.", e.InnerException);
            }
        }
    }

}
