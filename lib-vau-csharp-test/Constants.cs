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