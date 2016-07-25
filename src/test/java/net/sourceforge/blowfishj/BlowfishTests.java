
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

import java.util.Arrays;

/**
 * All test cases for the blowfishj core classes.
 */
public class BlowfishTests extends TestCase
{
	/**
	 * Selftest routine, for instance to check for a valid class file loading.
	 * @return true: selftest passed / false: selftest failed
	 */
	public static boolean selfTest()
	{
		// test vector #1 (checking for the "signed bug")
		byte[] testKey1 =
		{
			(byte) 0x1c, (byte) 0x58, (byte) 0x7f, (byte) 0x1c,
			(byte) 0x13, (byte) 0x92, (byte) 0x4f, (byte) 0xef
		};

		int[] tv_p1 = { 0x30553228, 0x6d6f295a };
		int[] tv_c1 = { 0x55cb3774, 0xd13ef201 };
		int[] tv_t1 = new int[2];

		// test vector #2 (offical vector by Bruce Schneier)
		String sTestKey2 = "Who is John Galt?";
		byte[] testKey2 = sTestKey2.getBytes();

		int[] tv_p2 = { 0xfedcba98, 0x76543210 };
		int[] tv_c2 = { 0xcc91732b, 0x8022f684 };
		int[] tv_t2 = new int[2];

		BlowfishECB testbf1;
		BlowfishECB testbf2;


		// start the tests, check for a proper decryption, too

		testbf1 = new BlowfishECB(testKey1, 0, testKey1.length);

		testbf1.encrypt(tv_p1, 0, tv_t1, 0, tv_p1.length);

		if ((tv_t1[0] != tv_c1[0]) || (tv_t1[1] != tv_c1[1]))
		{
			return false;
		}

		testbf1.decrypt(tv_t1, 0, tv_t1, 0, tv_t1.length);

		if ((tv_t1[0] != tv_p1[0]) || (tv_t1[1] != tv_p1[1]))
		{
			return false;
		}

		testbf2 = new BlowfishECB(testKey2, 0, testKey2.length);

		testbf2.encrypt(tv_p2, 0, tv_t2, 0, tv_p2.length);

		if ((tv_t2[0] != tv_c2[0]) || (tv_t2[1] != tv_c2[1]))
		{
			return false;
		}

		testbf2.decrypt(tv_t2, 0, tv_t2, 0, tv_t2.length);

		if ((tv_t2[0] != tv_p2[0]) || (tv_t2[1] != tv_p2[1]))
		{
			return false;
		}

		return true;
	}

	public void testByteArrayHandling()
	{
		byte[] key = { 0x01, 0x02, 0x03, (byte)0xaa, (byte)0xee, (byte)0xff };


		boolean blSame;
		int nI, nJ;
		BlowfishECB bfe;
		BlowfishCBC bfc;
		byte[] zeroIV;
		byte[] plain, plain2;
		byte[] cipher, cipherRef;


		assertTrue(selfTest());
		assertTrue(selfTest());

		plain = new byte[256];
		for (nI = 0; nI < plain.length; nI++)
		{
			plain[nI] = (byte)nI;
		}

		plain2 = new byte[257];

		cipher = new byte[257];

		cipherRef = null;

		zeroIV = new byte[8];
		Arrays.fill(zeroIV, 0, zeroIV.length, (byte)0);

		for (nI = 0; nI < 3; nI++)
		{
			bfe = bfc = null;

			// reset to avoid cheats

			Arrays.fill(zeroIV, 0, zeroIV.length, (byte)0);

			Arrays.fill(cipher, 0, cipher.length, (byte)0xcc);
			Arrays.fill(plain2, 0, cipher.length, (byte)0xcc);

			switch(nI)
			{
				case 0:
				{
					bfe = new BlowfishECB();
					bfe.initialize(key, 0, key.length);
					break;
				}
				case 1:
				{
					bfe = new BlowfishECB(key, 0, key.length);
					break;
				}
				case 2:
				{
					bfc = new BlowfishCBC(key, 0, key.length);
					bfc.setCBCIV(zeroIV, 0);
					break;
				}
				case 3:
				{
					bfc = new BlowfishCBC(key, 0, key.length);
					break;
				}
			}

			// encrypt and decrypt

			if (bfc == null)
			{
				bfe.encrypt(plain, 0, cipher, 0, plain.length);
				bfe.decrypt(cipher, 0, plain2, 0, plain.length);
			}
			else
			{
				cipherRef = null;

				// first check of the IV was set correctly
				assertTrue(bfc.getCBCIV() == 0L);

				bfc.encrypt(plain, 0, cipher, 0, plain.length);
				bfc.setCBCIV(0L);
				bfc.decrypt(cipher, 0, plain2, 0, plain.length);
			}

			// check for overwrites

			assertTrue(cipher[256] == (byte) 0xcc);
			assertTrue(plain2[256] == (byte) 0xcc);

			// verify that all encrypted results are equal,with the first one
			// of each kind (ECB/CBC) setting the reference

			if (cipherRef == null)
			{
				cipherRef = new byte[cipher.length];
				System.arraycopy(cipher, 0, cipherRef, 0, cipher.length);
			}
			else
			{
				for (nJ = 0; nJ < cipher.length; nJ++)
				{
					assertTrue(cipher[nJ] == cipherRef[nJ]);
				}
			}

			// make sure that the decypted value is actually correct (and that
			// we're not doing zero encryption)

			blSame = true;

			for (nJ = 0; nJ < plain.length; nJ++)
			{
				assertTrue(plain[nJ] == plain2[nJ]);
				if (cipher[nJ] != plain2[nJ])
				{
					blSame = false;
				}
			}
			assertFalse(blSame);
		}
	}



	final static byte[] KNOWN_WEAK_KEY =
	{
		(byte)0xe4, (byte)0x19, (byte)0xbc, (byte)0xec, (byte)0x18, (byte)0x7b,
		(byte)0x27, (byte)0x81, (byte)0x64, (byte)0x51,	(byte)0x54, (byte)0xe6,
		(byte)0x0a, (byte)0x42, (byte)0x79, (byte)0x6b, (byte)0x16, (byte)0xc8,
		(byte)0x54, (byte)0x85, (byte)0x3b, (byte)0x64, (byte)0xfa, (byte)0x1e,
		(byte)0x61, (byte)0x29, (byte)0x7e, (byte)0x36, (byte)0xe9, (byte)0xd3,
		(byte)0xcf, (byte)0xe2, (byte)0x2b, (byte)0x69, (byte)0x68, (byte)0x33,
		(byte)0x11, (byte)0xa1, (byte)0x57, (byte)0x83
	};

	public void testWeakKey()
	{
		BlowfishECB bfe;
		byte[] key;


		key = (byte[])KNOWN_WEAK_KEY.clone();

		bfe = new BlowfishECB(key, 0, key.length);
		assertTrue(bfe.weakKeyCheck());

		Arrays.fill(key, 0, key.length, (byte)0);

		bfe = new BlowfishECB(key, 0, key.length);
		assertFalse(bfe.weakKeyCheck());
	}



	public void testBlowfishEasy()
	{
		int nI, nJ;
		String sPlain, sCipher, sPlain2, sKey;
		StringBuffer sbuf = new StringBuffer();
		BlowfishEasy bfes;

		// test a growing string with all kinds of characters, even reaching in
		// the Unicode space

		for (nI = 0; nI < 513; nI++)
		{
			sbuf.setLength(0);

			for (nJ = 0; nJ < nI; nJ++)
			{
				sbuf.append((char)nJ);
			}

			sPlain = sbuf.toString();
			sKey = sPlain + "xyz";	// (easy way to get unique keys)

			// test standard encryption/decryption

			bfes = new BlowfishEasy(sKey.toCharArray());

			sCipher = bfes.encryptString(sPlain);
			sPlain2 = bfes.decryptString(sCipher);

			assertTrue(sPlain.equals(sPlain2));

			// test with reset instanced

			bfes = new BlowfishEasy(sKey.toCharArray());
			sPlain2 = bfes.decryptString(sCipher);

			assertTrue(sPlain.equals(sPlain2));

			// negative test with wrong key

			bfes = new BlowfishEasy((sKey + ".").toCharArray());
			sPlain2 = bfes.decryptString(sCipher);

			assertFalse(sPlain.equals(sPlain2));
		}
	}
	

	
	static byte[] KEYSETUPBUG_K0 = { 0, 1, 2 };
	static byte[] KEYSETUPBUG_K1 = { 1, 2 };
	
	public void testKeySetupBug()
	{
		// verify a bug in the key setup, which was fixed in 2.13
		
		int nI;
		byte[] block0, block1;
		BlowfishECB bfe0, bfe1;
		
		bfe0 = new BlowfishECB(KEYSETUPBUG_K0, 1, 2);
		bfe1 = new BlowfishECB(KEYSETUPBUG_K1, 0, 2);
		
		block0 = new byte[BlowfishECB.BLOCKSIZE];
		block1 = new byte[BlowfishECB.BLOCKSIZE];
		
		Arrays.fill(block0, 0, block0.length, (byte)0);
		Arrays.fill(block1, 0, block1.length, (byte)0);
		
		bfe0.encrypt(block0, 0, block0, 0, block0.length);
		bfe1.encrypt(block1, 0, block1, 0, block1.length);
		
		for (nI = 0; nI < block0.length; nI++)
		{
			assertTrue(block0[nI] == block1[nI]);
		}
	}
}
