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

using lib_vau_csharp.crypto;
using lib_vau_csharp.util;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using PeterO.Cbor;
using System;

namespace lib_vau_csharp.data
{
    public class VauEccPublicKey
    {
        public string Crv { get; set; }
        public byte[] X { get; set; }
        public byte[] Y { get; set; }

        public VauEccPublicKey(ECPublicKeyParameters eCPublicKeyParameters)
        {
            X = eCPublicKeyParameters.Q.XCoord.GetEncoded();
            Y = eCPublicKeyParameters.Q.YCoord.GetEncoded();
            Crv = "P-256";
        }

        public VauEccPublicKey(string crv, byte[] x, byte[] y)
        {
            Crv = crv;
            X = x;
            Y = y;
        }

        public ECPublicKeyParameters ToEcPublicKey()
        {
            EllipticCurve ecCurve = EllipticCurve.GenerateEllipticCurve(EllipticCurve.SECP256R1);
            return ecCurve.GetPublicKeyFromCoordinates(new BigInteger(1, X, 0, X.Length), new BigInteger(1, Y, 0, Y.Length));
        }

        public static CBORObject toCBOR(VauEccPublicKey ecPubKey)
        {
            return CBORObject.NewMap()
                .Add("crv", ecPubKey.Crv)
                .Add("x", ecPubKey.X)
                .Add("y", ecPubKey.Y);
        }

        public static VauEccPublicKey fromCbor(CBORObject cborObject)
        {
            try
            {
                VauEccPublicKey vauEccPublicKey = new VauEccPublicKey(
                        cborObject["crv"].AsString(),
                        CborUtils.DecodeByteValueFromCbor(cborObject["x"]),
                        CborUtils.DecodeByteValueFromCbor(cborObject["y"]));
                return vauEccPublicKey;
            }
            catch (Exception e)
            {
                throw new CBORException("Error when decoding CBOR to VauEccPublicKey.", e.InnerException);
            }
        }
    }
}
