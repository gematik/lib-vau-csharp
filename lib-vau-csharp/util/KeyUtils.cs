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

using lib_vau_csharp.data;
using Org.BouncyCastle.Security.Certificates;
using System;

namespace lib_vau_csharp.util
{
    public static class KeyUtils
    {
        public static void VerifyClientMessageIsWellFormed(VauEccPublicKey eccPublicKey, VauBasicPublicKey kyberPublicKey)
        {
            VerifyEccPublicKey(eccPublicKey);
            try
            {
                kyberPublicKey.ToKyberPublicKey();
            }
            catch (Exception e)
            {
                throw new ArgumentException("Kyber Public Key Bytes in VAU Message 1 are not well formed.", e);
            }
        }

        public static void verifyClientMessageIsWellFormed(VauMessage1 vauMessage1)
        {
            VerifyEccPublicKey(vauMessage1.EcdhPublicKey);
            try
            {
                vauMessage1.ToKyberPublicKey();
            }
            catch (Exception e)
            {
                throw new ArgumentException("Kyber Public Key Bytes in VAU Message 1 are not well formed.", e);
            }
        }

        public static void VerifyEccPublicKey(VauEccPublicKey eccPublicKey)
        {
            if (!string.Equals(eccPublicKey.Crv, "P-256"))
            {
                throw new ArgumentException($"CRV Value of ECDH Public Key in VAU Message 1 must be 'P-256'. Actual value is '{eccPublicKey.Crv}'");
            }
            if (eccPublicKey.X.Length != 32)
            {
                throw new ArgumentException($"Length of X Value of ECDH Public Key in VAU Message 1 must be 32. Actual length is '{eccPublicKey.X.Length}'");
            }
            if (eccPublicKey.Y.Length != 32)
            {
                throw new ArgumentException($"Length of Y Value of ECDH Public Key in VAU Message 1 must be 32. Actual length is '{eccPublicKey.Y.Length}'");
            }
        }

        public static void CheckCertificateExpired(int exp)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now > exp)
            {
                throw new CertificateException($"The server certificate has expired. (exp: {DateTimeOffset.FromUnixTimeSeconds(exp).ToLocalTime()}");
            }
        }
    }
}
