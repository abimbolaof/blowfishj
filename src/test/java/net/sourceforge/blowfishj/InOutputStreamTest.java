
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import net.sourceforge.blowfishj.BlowfishCBC;
import net.sourceforge.blowfishj.BlowfishInputStream;
import net.sourceforge.blowfishj.BlowfishOutputStream;

/**
 * Simple tests for the BlowfishInputStream and BlowfishOutputStream.
 * @author original version by Dale Anson <danson@germane-software.com>
 */
public class InOutputStreamTest extends TestCase
{
	static final int[] SIZES =
	{
		0, 1, 3, 5, 8, 9, 15, 16, 17, 24, 64, 1024, 65537
	};

	public void testStreams() throws IOException
	{
		int nI;
		int nJ;
		int nS;
		int nDec;
		BlowfishInputStream bfis;
		BlowfishOutputStream bfos;
		ByteArrayInputStream bais;
		ByteArrayOutputStream baos;
		byte[] key;
		byte[] plain;
		byte[] enc;


		// many sizes, many keys

		key = new byte[1000];

		for (nI = 0; nI < key.length; nI++)
		{
			key[nI] = (byte)nI;
		}

		for (nI = 0; nI < key.length; nI += nI + 1 - (nI & 1))
		{
			for (nS = 0; nS < SIZES.length; nS++)
			{
				plain = new byte[SIZES[nS]];

				for (nJ = 0; nJ < plain.length; nJ++)
				{
					plain[nJ] = (byte)nJ;
				}

				baos = new ByteArrayOutputStream();

				bfos = new BlowfishOutputStream(
					key,
					nI,
					key.length - nI,
					baos);

				bfos.write(plain);
				bfos.close();
				bfos.close();

				enc = baos.toByteArray();

				assertTrue(
					enc.length ==
						plain.length - (plain.length % BlowfishCBC.BLOCKSIZE) +
						(BlowfishCBC.BLOCKSIZE * 2));

				bais = new ByteArrayInputStream(enc);

				bfis = new BlowfishInputStream(
					key,
					nI,
					key.length - nI,
					bais);

				for (nJ = 0; nJ < plain.length; nJ++)
				{
					assertTrue((nDec = bfis.read()) != -1);
					assertTrue(plain[nJ] == (byte)nDec);
				}
				assertTrue(bfis.read() == -1);

				bfis.close();
				bfis.close();
			}
		}
	}



	// (this reference data was produced in C# with Blowfish.NET, its main
	// purpose is to test cross-platform compatibility)

	static final byte[] BFS_REF_KEY = { 0,1,2,3,4,5,6,7,8,9,10 };
	static final int BFS_REF_PLAIN_LEN = 117;

    static final byte[] BFS_REF_ENC_DATA =
            {
                    (byte) 0x4f, (byte) 0x02, (byte) 0x16, (byte) 0x03, (byte) 0xc1, (byte) 0xe8,
                    (byte) 0x73, (byte) 0x3e, (byte) 0xa4, (byte) 0x80, (byte) 0xd8, (byte) 0x7a,
                    (byte) 0x1e, (byte) 0x43, (byte) 0x2b, (byte) 0x22, (byte) 0xaf, (byte) 0x3b,
                    (byte) 0xcf, (byte) 0x3e, (byte) 0x75, (byte) 0x4c, (byte) 0x51, (byte) 0x72,
                    (byte) 0x9e, (byte) 0x2f, (byte) 0x94, (byte) 0x8a, (byte) 0xa6, (byte) 0x73,
                    (byte) 0xd4, (byte) 0x8e, (byte) 0x2e, (byte) 0x0b, (byte) 0x44, (byte) 0x84,
                    (byte) 0xee, (byte) 0xec, (byte) 0xba, (byte) 0x27, (byte) 0x6d, (byte) 0x12,
                    (byte) 0x30, (byte) 0xff, (byte) 0x22, (byte) 0xbb, (byte) 0x0a, (byte) 0x4f,
                    (byte) 0xb0, (byte) 0x86, (byte) 0x00, (byte) 0x12, (byte) 0x44, (byte) 0xd5,
                    (byte) 0x17, (byte) 0x80, (byte) 0x60, (byte) 0x12, (byte) 0x97, (byte) 0x0c,
                    (byte) 0x27, (byte) 0xb0, (byte) 0x7d, (byte) 0x8d, (byte) 0xe6, (byte) 0x2b,
                    (byte) 0x6d, (byte) 0x65, (byte) 0xd9, (byte) 0x5f, (byte) 0x4b, (byte) 0xba,
                    (byte) 0x96, (byte) 0x07, (byte) 0xe8, (byte) 0x1f, (byte) 0x02, (byte) 0xd8,
                    (byte) 0xf9, (byte) 0x74, (byte) 0x9b, (byte) 0x7f, (byte) 0x86, (byte) 0x71,
                    (byte) 0x7d, (byte) 0xe7, (byte) 0x01, (byte) 0x3a, (byte) 0xf8, (byte) 0xef,
                    (byte) 0x31, (byte) 0xf6, (byte) 0xb3, (byte) 0x16, (byte) 0x50, (byte) 0xa4,
                    (byte) 0xd9, (byte) 0x8b, (byte) 0xaa, (byte) 0xe1, (byte) 0x95, (byte) 0x66,
                    (byte) 0xca, (byte) 0xe3, (byte) 0x90, (byte) 0x7e, (byte) 0x47, (byte) 0x3c,
                    (byte) 0xc0, (byte) 0x1d, (byte) 0x26, (byte) 0x67, (byte) 0x65, (byte) 0xe8,
                    (byte) 0xb8, (byte) 0x73, (byte) 0x62, (byte) 0x7b, (byte) 0xa5, (byte) 0x3f,
                    (byte) 0xcc, (byte) 0xe1, (byte) 0x9a, (byte) 0x89, (byte) 0x73, (byte) 0x0c,
                    (byte) 0x6a, (byte) 0x84
            };

	public void testRefStream() throws IOException
	{
		int nI;
		BlowfishInputStream bfis;


		bfis = new BlowfishInputStream(
			BFS_REF_KEY,
			0,
			BFS_REF_KEY.length,
			new ByteArrayInputStream(BFS_REF_ENC_DATA));

		for (nI = 0; nI < BFS_REF_PLAIN_LEN; nI++)
		{
			assertTrue((nI & 0x0ff) == bfis.read());
		}

		assertTrue(bfis.read() == -1);

		bfis.close();
	}
}
