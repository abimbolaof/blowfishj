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

import java.io.*;
import java.util.*;
import java.security.*;

/**
 * An output stream that encrypts data using the Blowfish algorithm in CBC mode,
 * padded with PCKS7. Provided key material is hashed to a 160bit final key
 * using SHA-1.
 * @author original version by Dale Anson <danson@germane-software.com>
 */
public class BlowfishOutputStream extends OutputStream
{
	OutputStream m_os;

	BlowfishCBC m_bfc;

	byte[] m_bufIn;
	byte[] m_bufOut;
	int m_nBytesInBuf;

	///////////////////////////////////////////////////////////////////////////

	void init(
		byte[] key,
		int nOfs,
		int nLen,
		OutputStream os) throws IOException
	{
		byte[] ckey;
		long iv;
		SHA1 sh;
		SecureRandom srnd;


		m_os = os;

		m_nBytesInBuf = 0;

		sh = new SHA1();
		sh.update(key, nOfs, nLen);
		sh.finalize();

		ckey = sh.getDigest();
		sh.clear();

		m_bfc = new BlowfishCBC(
			ckey,
			0,
			ckey.length);

		Arrays.fill(
			ckey,
			0,
			ckey.length,
			(byte)0);

		m_bufIn = new byte[BlowfishCBC.BLOCKSIZE];
		m_bufOut = new byte[BlowfishCBC.BLOCKSIZE];

		// (make sure the IV is written to output stream -- this is always the
		// first 8 bytes written out)

		srnd = new SecureRandom();
		srnd.nextBytes(m_bufIn);

		m_os.write(m_bufIn, 0, m_bufIn.length);
		m_bfc.setCBCIV(m_bufIn, 0);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Default constructor. The key material gets transformed to a final 160bit
	 * key using SHA-1.
	 * @param key key buffer
	 * @param nOfs where the key material starts
	 * @param nLen size of the key material (in bytes)
	 * @param os the output stream to which bytes will be written
	 * @exception IOException if the IV couldn't be written
	 */
	public BlowfishOutputStream(
		byte[] key,
		int nOfs,
		int nLen,
		OutputStream os) throws IOException
	{
		init(key, nOfs, nLen, os);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Constructor using a string. The ASCII character values of the string are
	 * hashed with SHA-1, the digest is used as the final key.
	 * @param sPassPhrase the passphrase
	 * @param os the output stream to which bytes will be written
	 * @exception IOException if the IV couldn't be written
	 * @deprecated due to the restrictions in usage and the discarding of some
	 * original key material it is highly recommended not to use it anymore
	 */
	public BlowfishOutputStream(
		String sPassPhrase,
		OutputStream os) throws IOException
	{
		int nI, nC;
		byte[] key;


		key = new byte[nC = sPassPhrase.length()];

		for (nI = 0; nI < nC; nI++)
		{
			key[nI] = (byte)(sPassPhrase.charAt(nI) & 0x0ff);
		}

		init(key, 0, nC, os);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * @see java.io.OutputStream#write(int)
	 */
	public void write(
		int nByte) throws IOException
	{
		int nI;
		byte[] iv;


		// if buffer isn't full, just store the input
		++m_nBytesInBuf;
		if (m_nBytesInBuf < m_bufIn.length)
		{
			m_bufIn[m_nBytesInBuf - 1] = (byte)nByte;
			return;
		}

		// else this input will fill the buffer
		m_bufIn[m_nBytesInBuf - 1] = (byte)nByte;
		m_nBytesInBuf = 0;

		// encrypt the buffer
		m_bfc.encrypt(
			m_bufIn,
			0,
			m_bufOut,
			0,
			m_bufIn.length);

		// write the out_buffer to the wrapped output stream
		m_os.write(
			m_bufOut,
			0,
			m_bufOut.length);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * @see java.io.InputStream#close()
	 */
	public void close() throws IOException
	{
		int nI;
		byte nPadVal;


		// This output stream always writes out even blocks of 8 bytes. If it
		// happens that the last block does not have 8 bytes, then the block
		// will be padded to have 8 bytes.
		// The last byte is ALWAYS the number of pad bytes and will ALWAYS be a
		// number between 1 and 8, inclusive. If this means adding an extra
		// block just for the pad count, then so be it. Minor correction: 8
		// isn't the magic number, rather it's BlowfishECB.BLOCKSIZE.

		nPadVal = (byte)(m_bufIn.length - m_nBytesInBuf);

		while (m_nBytesInBuf < m_bufIn.length)
		{
			m_bufIn[m_nBytesInBuf] = nPadVal;
			++m_nBytesInBuf;
		}

		// encrypt the buffer
		m_bfc.encrypt(
			m_bufIn,
			0,
			m_bufOut,
			0,
			m_bufIn.length);

		// write the out_buffer to the wrapped output stream
		m_os.write(
			m_bufOut,
			0,
			m_bufOut.length);

		m_os.close();
		m_bfc.cleanUp();

		return;
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * @see java.io.OutputStream#flush()
	 */
	public void flush() throws IOException
	{
		m_os.flush();
	}
}
