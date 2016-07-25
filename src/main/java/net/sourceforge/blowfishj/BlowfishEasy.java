
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

import java.security.SecureRandom;
import java.util.Random;

/**
 * Support class for easy string encryption with the Blowfish algorithm. Works
 * in CBC mode with a SHA-1 key setup and correct padding - the purpose of
 * this class is mainly to show a possible implementation with Blowfish.
 */
public class BlowfishEasy
{
	BlowfishCBC m_bfc;



	static SecureRandom _srnd;

	static
	{
		// (this approach still needs to be proven; it is good if lots of
		// instances are created and the generator is created internally all the
		// time, but it can be less efficient if SecureRandom is just a wrapper
		// for one central source, with thread protection as an overhead)

		_srnd = new SecureRandom();
	}

	/**
	 * Constructor to use string data as the key.
	 * @param passw the password, usually gained by String.toCharArray()
	 */
	public BlowfishEasy(
		char[] passw)
	{
		int nI;
		int nC;
		SHA1 sh = null;
		byte[] hash;


		// hash down the password to a 160bit key, using SHA-1

		sh = new SHA1();

		for (nI = 0, nC = passw.length; nI < nC; nI++)
		{
			sh.update((byte)((passw[nI] >> 8) & 0x0ff));
			sh.update((byte)( passw[nI]       & 0x0ff));
		}

		sh.finalize();

		// setup the encryptor (using a dummy IV for now)

		hash = new byte[SHA1.DIGEST_SIZE];
		sh.getDigest(hash, 0);

		m_bfc = new BlowfishCBC(hash, 0, hash.length, 0);
	}



	/**
	 * Encrypts a string (treated in Unicode) using the internal random
	 * generator.
	 * @param sPlainText string to encrypt
	 * @return encrypted string in binhex format
	 */
	public String encryptString(
		String sPlainText)
	{
		long lCBCIV;


		synchronized (_srnd)
		{
			lCBCIV = _srnd.nextLong();
		}

		return encStr(sPlainText, lCBCIV);
	}



	/**
	 * Encrypts a string (in Unicode).
	 * @param sPlainText string to encrypt
	 * @param rndGen random generator (usually a java.security.SecureRandom
	 * instance)
	 * @return encrypted string in binhex format
	 */
	public String encryptString(
		String sPlainText,
		Random rndGen)
	{
		return encStr(sPlainText, rndGen.nextLong());
	}



	// internal routine for string encryption

	private String encStr(
			CharSequence sPlainText,
			long lNewCBCIV)
	{
		int nI;
		int nPos;
		int nStrLen;
		char cActChar;
		byte bPadVal;
		byte[] buf;
		byte[] newCBCIV;


		nStrLen = sPlainText.length();
		buf = new byte[((nStrLen << 1) & ~7) + 8];

		nPos = 0;
		for (nI = 0; nI < nStrLen; nI++)
		{
			cActChar = sPlainText.charAt(nI);
			buf[nPos] = (byte)((cActChar >> 8) & 0x0ff);
			nPos++;
			buf[nPos] = (byte) (cActChar & 0x0ff);
			nPos++;
		}

		bPadVal = (byte) (buf.length - (nStrLen << 1));
		while (nPos < buf.length)
		{
			buf[nPos] = bPadVal;
			nPos++;
		}

		m_bfc.setCBCIV(lNewCBCIV);

		m_bfc.encrypt(buf, 0, buf, 0, buf.length);

		newCBCIV = new byte[BlowfishCBC.BLOCKSIZE];

		BinConverter.longToByteArray(lNewCBCIV, newCBCIV, 0);

		return BinConverter.bytesToHexStr(newCBCIV, 0, BlowfishCBC.BLOCKSIZE)
			 + BinConverter.bytesToHexStr(buf, 0, buf.length);
	}



	/**
	 * Decrypts a hexbin string (handling is case sensitive).
	 * @param sCipherText hexbin string to decrypt
	 * @return decrypted string (null equals an error)
	 */
	public String decryptString(
		String sCipherText)
	{
		int nNumOfBytes;
		int nPadByte;
		int nLen;
		byte[] buf;
		byte[] cbciv;


		nLen = (sCipherText.length() >> 1) & ~7;

		if (nLen < BlowfishECB.BLOCKSIZE)
		{
			return null;
		}

		cbciv = new byte[BlowfishCBC.BLOCKSIZE];

		nNumOfBytes =
			BinConverter.hexStrToBytes(
				sCipherText,
				cbciv,
				0,
				0,
				BlowfishCBC.BLOCKSIZE);

		if (nNumOfBytes < BlowfishCBC.BLOCKSIZE) {
			return null;
		}

		m_bfc.setCBCIV(cbciv, 0);

		nLen -= BlowfishCBC.BLOCKSIZE;
		if (nLen == 0)
		{
			return "";
		}

		buf = new byte[nLen];

		nNumOfBytes =
			BinConverter.hexStrToBytes(
				sCipherText,
				buf,
				BlowfishCBC.BLOCKSIZE << 1,
				0,
				nLen);

		if (nNumOfBytes < nLen)
		{
			return null;
		}

		m_bfc.decrypt(buf, 0, buf, 0, buf.length);

		nPadByte = buf[buf.length - 1] & 0x0ff;

		// (try to get everything, even if the padding seem to be wrong)
		if (nPadByte > BlowfishCBC.BLOCKSIZE)
		{
			nPadByte = 0;
		}

		nNumOfBytes -= nPadByte;

		if (nNumOfBytes < 0)
		{
			return "";
		}

		return BinConverter.byteArrayToStr(buf, 0, nNumOfBytes);
	}



	/**
	 * Destroys (clears) the encryption engine, after that the instance is not
	 * valid anymore.
	 */
	public void destroy()
	{
		m_bfc.cleanUp();
	}
}
