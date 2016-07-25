
/*
 * Copyright 1997-2005 Markus Hahn 
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

package net.sourceforge.blowfishj;

import junit.framework.TestCase;
import net.sourceforge.blowfishj.BlowfishECB;

/**
 * Tests the official vectors from the Counterpane website.
 */
public class TestVectors extends TestCase
{
	public void testAllVectors()
	{
		int nI, nJ;
		byte[] key, plain, cipher, testBuf;
		long lKey, lPlain, lCipher;
		BlowfishECB bfecb;


		key = new byte[8];
		plain = new byte[8];
		cipher = new byte[8];
		testBuf = new byte[8];

		nI = 0;

		while (nI < TEST_DATA.length)
		{
			lKey = TEST_DATA[nI++];
			lPlain = TEST_DATA[nI++];
			lCipher = TEST_DATA[nI++];

			for (nJ = 7; nJ >= 0; nJ--)
			{
				key[nJ] = (byte) (lKey & 0x0ff);
				lKey >>>= 8;
				plain[nJ] = (byte) (lPlain & 0x0ff);
				lPlain >>>= 8;
				cipher[nJ] = (byte) (lCipher & 0x0ff);
				lCipher >>>= 8;
			}

			bfecb = new BlowfishECB(key, 0, key.length);

			bfecb.encrypt(plain, 0, testBuf, 0, plain.length);

			for (nJ = 0; nJ < 8; nJ++)
			{
				assertTrue(testBuf[nJ] == cipher[nJ]);
			}
		}
	}


	// (the official test vectors from the Counterpane website)

	final static long[] TEST_DATA =
	{
		0x0000000000000000L, 0x0000000000000000L, 0x4ef997456198dd78L,
		0xffffffffffffffffL, 0xffffffffffffffffL, 0x51866fd5b85ecb8aL,
		0x3000000000000000L, 0x1000000000000001L, 0x7d856f9a613063f2L,
		0x1111111111111111L, 0x1111111111111111L, 0x2466dd878b963c9dL,
		0x0123456789abcdefL, 0x1111111111111111L, 0x61f9c3802281b096L,
		0x1111111111111111L, 0x0123456789abcdefL, 0x7d0cc630afda1ec7L,
		0x0000000000000000L, 0x0000000000000000L, 0x4ef997456198dd78L,
		0xfedcba9876543210L, 0x0123456789abcdefL, 0x0aceab0fc6a0a28dL,
		0x7ca110454a1a6e57L, 0x01a1d6d039776742L, 0x59c68245eb05282bL,
		0x0131d9619dc1376eL, 0x5cd54ca83def57daL, 0xb1b8cc0b250f09a0L,
		0x07a1133e4a0b2686L, 0x0248d43806f67172L, 0x1730e5778bea1da4L,
		0x3849674c2602319eL, 0x51454b582ddf440aL, 0xa25e7856cf2651ebL,
		0x04b915ba43feb5b6L, 0x42fd443059577fa2L, 0x353882b109ce8f1aL,
		0x0113b970fd34f2ceL, 0x059b5e0851cf143aL, 0x48f4d0884c379918L,
		0x0170f175468fb5e6L, 0x0756d8e0774761d2L, 0x432193b78951fc98L,
		0x43297fad38e373feL, 0x762514b829bf486aL, 0x13f04154d69d1ae5L,
		0x07a7137045da2a16L, 0x3bdd119049372802L, 0x2eedda93ffd39c79L,
		0x04689104c2fd3b2fL, 0x26955f6835af609aL, 0xd887e0393c2da6e3L,
		0x37d06bb516cb7546L, 0x164d5e404f275232L, 0x5f99d04f5b163969L,
		0x1f08260d1ac2465eL, 0x6b056e18759f5ccaL, 0x4a057a3b24d3977bL,
		0x584023641aba6176L, 0x004bd6ef09176062L, 0x452031c1e4fada8eL,
		0x025816164629b007L, 0x480d39006ee762f2L, 0x7555ae39f59b87bdL,
		0x49793ebc79b3258fL, 0x437540c8698f3cfaL, 0x53c55f9cb49fc019L,
		0x4fb05e1515ab73a7L, 0x072d43a077075292L, 0x7a8e7bfa937e89a3L,
		0x49e95d6d4ca229bfL, 0x02fe55778117f12aL, 0xcf9c5d7a4986adb5L,
		0x018310dc409b26d6L, 0x1d9d5c5018f728c2L, 0xd1abb290658bc778L,
		0x1c587f1c13924fefL, 0x305532286d6f295aL, 0x55cb3774d13ef201L,
		0x0101010101010101L, 0x0123456789abcdefL, 0xfa34ec4847b268b2L,
		0x1f1f1f1f0e0e0e0eL, 0x0123456789abcdefL, 0xa790795108ea3caeL,
		0xe0fee0fef1fef1feL, 0x0123456789abcdefL, 0xc39e072d9fac631dL,
		0x0000000000000000L, 0xffffffffffffffffL, 0x014933e0cdaff6e4L,
		0xffffffffffffffffL, 0x0000000000000000L, 0xf21e9a77b71c49bcL,
		0x0123456789abcdefL, 0x0000000000000000L, 0x245946885754369aL,
		0xfedcba9876543210L, 0xffffffffffffffffL, 0x6b5c5a9c5d9e0a5aL
	};
}
