package net.sourceforge.blowfishj;

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

import java.util.*;
import java.security.*;

/**
 * Support class for easy string encryption with the Blowfish algorithm. Works
 * in CBC mode with a SHA-1 key setup and correct padding - the purpose of
 * this class is mainly to show a possible implementation with Blowfish.
 */
public class BlowfishEasy
{
	BlowfishCBC m_bfc;

	///////////////////////////////////////////////////////////////////////////

	static SecureRandom _srnd;

	static
	{
		// (this approach still needs to be proven; it is good if lots of
		// instances are created and the generator is created internally all the
		// time, but it can be less efficient if SecureRandom is just a wrapper
		// for one central source, with thread protection as an overhead)

		_srnd = new SecureRandom();
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Constructor to set up a string as the key.
	 * @param sPassword the password
	 * @deprecated use the BlowfishEasy(char[]) instead, since this constructor
	 * discards the higher 8 bits of every 16bit Unicode character; <b>be
	 * aware that this constructor will produce non-compatible results to the
	 * new method!</b>
	 */
	public BlowfishEasy(
		String sPassword)
	{
		int nI, nC;
		SHA1 sh = null;
		byte[] hash;


		sh = new SHA1();

		for (nI = 0, nC = sPassword.length(); nI < nC; nI++)
		{
			sh.update((byte) (sPassword.charAt(nI) & 0x0ff));
		}
		sh.finalize();

		hash = new byte[SHA1.DIGEST_SIZE];
		sh.getDigest(hash, 0);

		m_bfc = new BlowfishCBC(hash, 0, hash.length, 0);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Constructor to use string data as the key.
	 * @param passw the password, usually gained by String.toCharArray()
	 */
	public BlowfishEasy(
		char[] passw)
	{
		int nI, nC;
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

	///////////////////////////////////////////////////////////////////////////

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

	///////////////////////////////////////////////////////////////////////////

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

	///////////////////////////////////////////////////////////////////////////

	// internal routine for string encryption

	private String encStr(
		String sPlainText,
		long lNewCBCIV)
	{
		int nI, nPos, nStrLen;
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
			buf[nPos++] = (byte)((cActChar >> 8) & 0x0ff);
			buf[nPos++] = (byte) (cActChar & 0x0ff);
		}

		bPadVal = (byte) (buf.length - (nStrLen << 1));
		while (nPos < buf.length)
		{
			buf[nPos++] = bPadVal;
		}

		m_bfc.setCBCIV(lNewCBCIV);

		m_bfc.encrypt(buf, 0, buf, 0, buf.length);

		newCBCIV = new byte[BlowfishCBC.BLOCKSIZE];

		BinConverter.longToByteArray(lNewCBCIV, newCBCIV, 0);

		return BinConverter.bytesToHexStr(newCBCIV, 0, BlowfishCBC.BLOCKSIZE)
			 + BinConverter.bytesToHexStr(buf, 0, buf.length);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Decrypts a hexbin string (handling is case sensitive).
	 * @param sCipherText hexbin string to decrypt
	 * @return decrypted string (null equals an error)
	 */
	public String decryptString(
		String sCipherText)
	{
		int nNumOfBytes, nPadByte, nLen;
		byte[] buf;
		byte[] cbciv;


		nLen = (sCipherText.length() >> 1) & ~7;

		if (BlowfishECB.BLOCKSIZE > nLen)
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

		if (nNumOfBytes < BlowfishCBC.BLOCKSIZE)
			return null;

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
		if (BlowfishCBC.BLOCKSIZE < nPadByte)
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

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Destroys (clears) the encryption engine, after that the instance is not
	 * valid anymore.
	 */
	public void destroy()
	{
		m_bfc.cleanUp();
	}
}
