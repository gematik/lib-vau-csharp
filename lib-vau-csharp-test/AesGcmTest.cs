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
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Org.BouncyCastle.Utilities.Encoders;
using System;

namespace lib_vau_csharp.Tests
{
    public class AesGcmTest
    {
        private byte[] key = null;
        private byte[] iv = null;
        private byte[] clearText = null;
        private byte[] assocData = null;
        private byte[] encData = null;

        [SetUp]
        public void Setup()
        {
            // This data is generated from java implementation 
            key = Hex.Decode("9bd2c0a72f2608a56ab87eec688b1eb2290e96b5fd7a7e7203a4b92980c68bcd");
            iv = Hex.Decode("bf4847ea0000000000000001");
            clearText = Hex.Decode("48656c6c6f20576f726c64");
            assocData = Hex.Decode("02000100000000000000017db2e7bee1521f179acedff286be1065a52bde4f61cfc4db2853cb60d6aa1711");

            // This is the result from encryption to compare
            encData = Hex.Decode("e5eaf11d4361b2544f986206715ee4f663d57f9b276c90728f7e82");
        }

        [Test]
        public void TestwithReferenceData()
        {
            AesGcm aesGcm = new AesGcm();
            aesGcm.initAESForDecryption(iv, assocData, key);
            byte[] encryptedData = aesGcm.encryptData(clearText);
            ClassicAssert.IsNotNull(encryptedData);
            ClassicAssert.AreEqual(encryptedData, encData);

            byte[] decryptedData = aesGcm.decryptData(encryptedData);
            ClassicAssert.IsNotNull(decryptedData);
            ClassicAssert.IsTrue(clearText.Length == decryptedData.Length);
            ClassicAssert.AreEqual(clearText, decryptedData);
        }

        [Test]
        public void EncryptionNegativTests()
        {
            AesGcm aesGcm = new AesGcm();
            aesGcm.initAESForDecryption(iv, assocData, key);
            Assert.Throws<ArgumentNullException>(() => aesGcm.encryptData(null));                 // Must be thrown because no data to encrypt
        }

        [Test]
        public void DecryptionNegativTests()
        {
            AesGcm aesGcm = new AesGcm();
            aesGcm.initAESForDecryption(iv, assocData, key);
            Assert.Throws<ArgumentNullException>(() => aesGcm.decryptData(null));                 // Must be thrown because no data to encrypt
        }

        [Test]
        public void NegativInstanziationTests()
        {
            AesGcm aesGcm = new AesGcm();
            var tooShortIv = new byte[] { 0x00 };
            Assert.Throws<ArgumentNullException>(() => aesGcm.initAESForDecryption(null, assocData, key));         // Must be thrown because of missing random
            Assert.Throws<ArgumentNullException>(() => aesGcm.initAESForDecryption(tooShortIv, assocData, key));   // Must be thrown because of to few byte for random

            var tooShortKey = new byte[] { 0x00 };
            Assert.Throws<ArgumentNullException>(() => aesGcm.initAESForDecryption(iv, assocData, null));          // Must be thrown because of missing key
            Assert.Throws<ArgumentNullException>(() => aesGcm.initAESForDecryption(iv, assocData, tooShortKey));   // Must be thrown because of to few byte for key
        }
    }
}