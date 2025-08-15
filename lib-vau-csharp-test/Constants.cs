/*
 * Copyright 2025 gematik GmbH
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

using System.IO;

using lib_vau_csharp_test.util;

using lib_vau_csharp.data;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace lib_vau_csharp_test
{
    public static class Constants
    {
        public static class Keys
        {
            public static readonly EccKyberKeyPair EccKyberKeyPair = FileUtil.ReadEccKyberKeyPairFromFile(Paths.VauServerKeys);
            public static readonly ECPrivateKeyParameters ECPrivateKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(FileUtil.ReadAllBytes(Paths.VauSigKey));
        }

        public static class Certificates
        {
            public static readonly byte[] ServerAutCertificate = FileUtil.ReadAllBytes(Paths.VauSigCert);
            public static readonly byte[] OcspResponseAutCertificate = FileUtil.ReadAllBytes(Paths.OcspResponseVauSig);
        }

        public static class Paths
        {
            public static readonly string VauServerKeys = Path.Combine("resources", "vau_server_keys.cbor");
            public static readonly string VauSigKey = Path.Combine("resources", "vau-sig-key.der");
            public static readonly string VauSigCert = Path.Combine("resources", "vau_sig_cert.der");
            public static readonly string OcspResponseVauSig = Path.Combine("resources", "ocsp-response-vau-sig.der");
        }
    }
}