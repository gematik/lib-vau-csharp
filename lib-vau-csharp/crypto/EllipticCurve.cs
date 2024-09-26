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

using lib_vau_csharp.exceptions;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace lib_vau_csharp.crypto
{
    public class EllipticCurve
    {
        private X9ECParameters curveSpec = null;
        private ECDomainParameters curveParam = null;

        public const string SECP256R1 = "secp256r1";

        public static EllipticCurve GenerateEllipticCurve(string curveName)
        {
            EllipticCurve ecCurve = new EllipticCurve();
            ecCurve.curveSpec = ECNamedCurveTable.GetByName(curveName);
            ecCurve.curveParam = new ECDomainParameters(ecCurve.curveSpec);
            return ecCurve;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            ECKeyPairGenerator eCKeyPairGenerator = new ECKeyPairGenerator();
            ECKeyGenerationParameters eCKeyGenerationParameters = new ECKeyGenerationParameters(curveParam, new SecureRandom());
            eCKeyPairGenerator.Init(eCKeyGenerationParameters);
            return eCKeyPairGenerator.GenerateKeyPair();
        }

        public static ECPublicKeyParameters CalculatePublic(ECPrivateKeyParameters privateKey)
        {
            ECPoint q = privateKey.Parameters.G.Multiply(privateKey.D);
            return new ECPublicKeyParameters(q, privateKey.Parameters);
        }

        public ECPublicKeyParameters GetPublicKeyFromCoordinates(BigInteger x, BigInteger y)
        {
            ECPoint eCPoint = curveSpec.Curve.CreatePoint(x, y);
            return new ECPublicKeyParameters(eCPoint, curveParam);
        }

        public byte[] GetSharedSecret(ECPublicKeyParameters remoteEcdhPublicKey, ECPrivateKeyParameters localEcdhPrivateKey)
        {
            ECDHBasicAgreement eCDHBasicAgreement = new ECDHBasicAgreement();
            ECPrivateKeyParameters ecdhPrivateKeyParameters = new ECPrivateKeyParameters(localEcdhPrivateKey.D, curveParam);
            eCDHBasicAgreement.Init(ecdhPrivateKeyParameters);
            ECPoint eCPoint = curveSpec.Curve.CreatePoint(remoteEcdhPublicKey.Q.XCoord.ToBigInteger(), remoteEcdhPublicKey.Q.YCoord.ToBigInteger());
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(eCPoint, curveParam);
            BigInteger sharedSecret = eCDHBasicAgreement.CalculateAgreement(publicKeyParameters);

            byte[] outBytes = sharedSecret.ToByteArrayUnsigned();
            if (outBytes.Length != 32)
            {
                throw new KemException("Key size must be 32 byte!");
            }
            return outBytes;
        }

    }
}
