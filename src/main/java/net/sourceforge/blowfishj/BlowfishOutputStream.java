
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



	void init(
		byte[] key,
		int nOfs,
		int nLen,
		OutputStream os) throws IOException
	{
		byte[] ckey;
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

	/**
	 * @see OutputStream#write(int)
	 */
	public void write(
		int nByte) throws IOException
	{
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



	/**
	 * @see InputStream#close()
	 */
	public void close() throws IOException
	{
		byte nPadVal;

		if (m_os == null)
		{
			return;
		}

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
		m_os = null;
		
		m_bfc.cleanUp();
	}



	/**
	 * @see OutputStream#flush()
	 */
	public void flush() throws IOException
	{
		m_os.flush();
	}
}
