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

/**
 * An input stream that reads from a file created an instance of the
 * BlowfishJ.BlowfishOutputStream class.
 * @author original version by Dale Anson <danson@germane-software.com>
 */
public class BlowfishInputStream extends InputStream
{
	PushbackInputStream m_is;

	BlowfishCBC m_bfc;

	byte[] m_buf;
	int m_nBufPos;
	int m_nBufCount;

	///////////////////////////////////////////////////////////////////////////

	void init(
		byte[] key,
		int nOfs,
		int nLen,
		InputStream is) throws IOException
	{
		int nI, nC, nVal;
		SHA1 sh;
		byte[] ckey;


		m_nBufPos = m_nBufCount = 0;

		m_is = new PushbackInputStream(new BufferedInputStream(is));

		sh = new SHA1();
		sh.update(key, nOfs, nLen);
		sh.finalize();

		ckey = sh.getDigest();
		m_bfc = new BlowfishCBC(ckey, 0, ckey.length, 0);

		m_buf = new byte[BlowfishCBC.BLOCKSIZE];

		// read the IV

		for (nI = 0, nC = m_buf.length; nI < nC; nI++)
		{
			if (-1 == (nVal = m_is.read()))
			{
				throw new IOException("truncated stream, IV is missing");
			}
			m_buf[nI] = (byte)nVal;
		}

		m_bfc.setCBCIV(m_buf, 0);
	}

	///////////////////////////////////////////////////////////////////////////

	void fillBuffer() throws IOException
	{
		int nI, nC, nVal;



		// fill the whole buffer

		for (nI = 0, nC = m_buf.length; nI < nC; nI++)
		{
			if (-1 == (nVal = m_is.read()))
			{
				throw new IOException("truncated stream, unexpected end");
			}
			m_buf[nI] = (byte)nVal;
		}

		// decrypt the buffer
		m_bfc.decrypt(m_buf, 0, m_buf, 0, m_buf.length);

		// peek if this is the end of the stream

		if (-1 == (nVal = m_is.read()))
		{
			// this is the last block, so we can read out how much we actually
			// got left

			nC = m_buf[m_buf.length - 1];

			// validate the padding

			if (nC > m_buf.length || 0 > nC)
			{
				throw new IOException("unknown padding value detected");
			}

			m_nBufCount = m_buf.length - nC;

			for (nI = m_nBufCount; nI < m_buf.length; nI++)
			{
				if (m_buf[nI] != (byte)nC)
				{
					throw new IOException("invalid padding data detected");
				}
			}

			m_bfc.cleanUp();
			m_bfc = null;
		}
		else
		{
			// (a little bit clumsy, but avoid keeping and managing a more
			// complex double buffer logic)
			m_is.unread(nVal);

			m_nBufCount = m_buf.length;
		}

		m_nBufPos = 0;
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Default constructor. The key material gets transformed to a final 160bit
	 * key using SHA-1.
	 * @param key key buffer
	 * @param nOfs where the key material starts
	 * @param nLen size of the key material (in bytes)
	 * @param is the input stream from which bytes will be read
	 * @exception IOException if the IV couldn't be read out
	 */
	public BlowfishInputStream(
		byte[] key,
		int nOfs,
		int nLen,
		InputStream is) throws IOException
	{
		init(key, nOfs, nLen, is);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * Constructor using a string. The ASCII character values of the string are
	 * hashed with SHA-1, the digest is used as the final key.
	 * @param sPassPhrase the passphrase
	 * @param is the input stream from which bytes will be read
	 * @exception IOException if the IV couldn't be read out
	 * @deprecated due to the restrictions in usage and the discarding of some
	 * original key material it is highly recommended not to use it anymore
	 */
	public BlowfishInputStream(
		String sPassPhrase,
		InputStream is) throws IOException
	{
		int nI, nC;
		byte[] key;


		key = new byte[nC = sPassPhrase.length()];

		for (nI = 0; nI < nC; nI++)
		{
			key[nI] = (byte)(sPassPhrase.charAt(nI) & 0x0ff);
		}

		init(key, 0, nC, is);
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * @see java.io.InputStream#read()
	 */
	public int read() throws IOException
	{
		for (;;)
		{
			// out of (buffered) data?
			if  (m_nBufCount <= m_nBufPos)
			{
				// eos?

				if (null == m_bfc)
				{
					return -1;
				}
				else
				{
					fillBuffer();
				}
			}
			else
			{
				return (int)(m_buf[m_nBufPos++]) & 0x0ff;
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////

	/**
	 * @see java.io.InputStream#close()
	 */
	public void close() throws IOException
	{
		m_is.close();
		return;
	}
}
