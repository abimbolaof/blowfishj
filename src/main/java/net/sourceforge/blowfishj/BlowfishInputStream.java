
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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

/**
 * An input stream that reads from a file created an instance of the
 * net.sourceforge.blowfishj.BlowfishOutputStream class.
 * @author original version by Dale Anson <danson@germane-software.com>
 */
public class BlowfishInputStream extends InputStream
{
	PushbackInputStream m_is;

	BlowfishCBC m_bfc;

	byte[] m_buf;
	int m_nBufPos;
	int m_nBufCount;



	void init(
		byte[] key,
		int nOfs,
		int nLen,
		InputStream is) throws IOException
	{
		int nI;
		int nC;
		int nVal;
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
			if ((nVal = m_is.read()) == -1)
			{
				throw new IOException("truncated stream, IV is missing");
			}
			m_buf[nI] = (byte)nVal;
		}

		m_bfc.setCBCIV(m_buf, 0);
	}



	void fillBuffer() throws IOException
	{
		int nI;
		int nC;
		int nVal;


		// fill the whole buffer

		for (nI = 0, nC = m_buf.length; nI < nC; nI++)
		{
			if ((nVal = m_is.read()) == -1)
			{
				throw new IOException("truncated stream, unexpected end");
			}
			m_buf[nI] = (byte)nVal;
		}

		// decrypt the buffer
		m_bfc.decrypt(m_buf, 0, m_buf, 0, m_buf.length);

		// peek if this is the end of the stream

		if ((nVal = m_is.read()) == -1)
		{
			// this is the last block, so we can read out how much we actually
			// got left

			nC = m_buf[m_buf.length - 1];

			// validate the padding

			if (nC > m_buf.length || nC < 0)
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

	/**
	 * @see InputStream#read()
	 */
	public int read() throws IOException
	{
		for (;;)
		{
			// out of (buffered) data?
			if  (m_nBufCount <= m_nBufPos)
			{
				// eos?

				if (m_bfc == null)
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
				int result = (int) m_buf[m_nBufPos] & 0x0ff;
				m_nBufPos++;
				return result;
			}
		}
	}



	/**
	 * @see InputStream#close()
	 */
	public void close() throws IOException
	{
		if (m_is != null)
		{
			m_is.close();
			m_is = null;
		}
	}
}
