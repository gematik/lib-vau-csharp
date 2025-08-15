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

using lib_vau_csharp.crypto;
using lib_vau_csharp.data;
using lib_vau_csharp.exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using PeterO.Cbor;
using System;
using System.IO;

namespace lib_vau_csharp_test.util
{
    public class FileUtil
    {
        private static String getAbsoluteFilePath(String relativefilePath)
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, relativefilePath);
        }

        public static byte[] ReadAllBytes(String relativefilePath)
        {
            return File.ReadAllBytes(getAbsoluteFilePath(relativefilePath));
        }

        public static EccKyberKeyPair ReadEccKyberKeyPairFromFile(string filePath)
        {
            try
            {
                using (var stream = new FileStream(getAbsoluteFilePath(filePath), FileMode.Open))
                {
                    CBORObject cbor = CBORObject.Read(stream);
                    byte[] ecdhPrivateKey = cbor["ECDH_PrivKey"].ToObject<byte[]>();
                    AsymmetricCipherKeyPair ecdhKeyPair = readEcdsaKeypairFromPkcs8Pem(ecdhPrivateKey);
                    byte[] kyberPublicKey = cbor["Kyber768_PK"].ToObject<byte[]>();
                    byte[] kyberPrivateKey = cbor["Kyber768_PrivKey"].ToObject<byte[]>();
                    AsymmetricCipherKeyPair kyberKeyPair = readKyberKeypairFromPkcs8Pem(kyberPublicKey, kyberPrivateKey);

                    if (stream.Position != stream.Length)
                    {
                        //TODO: Log this/Exception?
                        stream.Dispose();
                    }

                    return new EccKyberKeyPair(ecdhKeyPair, kyberKeyPair);
                };
            }
            catch (Exception e)
            {
                throw new KyberException("Could not read Kyber key pair from file", e);
            }
        }

        private static AsymmetricCipherKeyPair readEcdsaKeypairFromPkcs8Pem(byte[] privateKeyBytes)
        {
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes);
            ECPublicKeyParameters eCPublicKeyParameters = EllipticCurve.CalculatePublic(eCPrivateKeyParameters);
            AsymmetricCipherKeyPair ecdhKeyPair = new AsymmetricCipherKeyPair(eCPublicKeyParameters, eCPrivateKeyParameters);
            return ecdhKeyPair;
        }

        private static AsymmetricCipherKeyPair readKyberKeypairFromPkcs8Pem(byte[] publicKeyBytes, byte[] privateKeyBytes)
        {
            KyberPublicKeyParameters kyberPublicKeyParameters = new KyberPublicKeyParameters(KyberParameters.kyber768, publicKeyBytes);
            KyberPrivateKeyParameters kyberPrivateKeyParameters = new KyberPrivateKeyParameters(KyberParameters.kyber768, privateKeyBytes);
            return new AsymmetricCipherKeyPair(kyberPublicKeyParameters, kyberPrivateKeyParameters);
        }
    }
}
