package test.net.sourceforge.blowfishj;

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

import java.util.Arrays;

import junit.framework.TestCase;
import net.sourceforge.blowfishj.BlowfishCBC;
import net.sourceforge.blowfishj.BlowfishECB;
import net.sourceforge.blowfishj.BlowfishEasy;

/**
 * All test cases for the BlowfishJ core classes.
 */
public class BlowfishTests extends TestCase
{
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


		assertTrue(BlowfishECB.selfTest());
		assertTrue(BlowfishCBC.selfTest());

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

			if (null == bfc)
			{
				bfe.encrypt(plain, 0, cipher, 0, plain.length);
				bfe.decrypt(cipher, 0, plain2, 0, plain.length);
			}
			else
			{
				cipherRef = null;

				// first check of the IV was set correctly
				assertTrue(0L == bfc.getCBCIV());

				bfc.encrypt(plain, 0, cipher, 0, plain.length);
				bfc.setCBCIV(0L);
				bfc.decrypt(cipher, 0, plain2, 0, plain.length);
			}

			// check for overwrites

			assertTrue((byte)0xcc == cipher[256]);
			assertTrue((byte)0xcc == plain2[256]);

			// verify that all encrypted results are equal,with the first one
			// of each kind (ECB/CBC) setting the reference

			if (null == cipherRef)
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

	///////////////////////////////////////////////////////////////////////////

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

	///////////////////////////////////////////////////////////////////////////

	public void testBlowfishEasy()
	{
		int nI, nJ;
		String sPlain, sCipher, sPlain2, sPlain3, sKey;
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
	
	///////////////////////////////////////////////////////////////////////////
	
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
