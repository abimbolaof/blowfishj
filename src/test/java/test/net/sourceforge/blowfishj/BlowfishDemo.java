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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.sourceforge.blowfishj.BinConverter;
import net.sourceforge.blowfishj.BlowfishCBC;
import net.sourceforge.blowfishj.BlowfishECB;
import net.sourceforge.blowfishj.BlowfishEasy;
import net.sourceforge.blowfishj.BlowfishInputStream;
import net.sourceforge.blowfishj.BlowfishOutputStream;


/**
 * Demonstrating the Blowfish encryption algorithm classes.
 */
public class BlowfishDemo
{
	// max. size of message to encrypt

	final static int MAX_MESS_SIZE = 64;

	// benchmark settings

	final static int TESTBUFSIZE = 100000;
	final static int TESTLOOPS = 10000;

	// BlowfishEasy reference

	final static String BFEASY_REF_PASSW = "secret";
	final static String BFEASY_REF_TEXT = "Protect me.";

	// startup CBC IV

	final static long CBCIV_START = 0x0102030405060708L;

	// things necessary for compatibility testing

	final static byte[] XCHG_KEY =
	{
		(byte)0xaa, (byte)0xbb, (byte)0xcc, 0x00, 0x42, 0x33
	};
	final static int XCHG_DATA_SIZE = 111;


	/**
	 * the application entry point
	 * @param args (command line) parameters
	 */
	public static void main(
		String args[])
	{
		int nI, nJ;
		int nRest, nMsgSize, nLnBrkLen;
		long lTm, lRate;
		double dAmount, dTime, dRate;
		String sEnc, sDec;
		byte[] testKey, tempBuf, cpyBuf, msgBuf, showIV;
		BlowfishECB bfe;
		BlowfishCBC bfc;
		BlowfishEasy bfes;
		BlowfishInputStream bfis;
		BlowfishOutputStream bfos;
		ByteArrayOutputStream baos;


		// first do the self test

		System.out.print("running self test...");

		if (!BlowfishECB.selfTest())
		{
			System.out.println(", FAILED");
			return;
		}

		System.out.println(", passed.");

		// now the classic examples...

		// create our test key

		testKey = new byte[5];
		for (nI = 0; nI < testKey.length; nI++)
		{
			testKey[nI] = (byte) (nI + 1);
		}

		// do the key setups and check for weaknesses

		System.out.print("setting up Blowfish keys...");

		bfe = new BlowfishECB(testKey, 0, testKey.length);

		bfc = new BlowfishCBC(
			testKey,
			0,
			testKey.length,
			CBCIV_START);

		System.out.println(", done.");

		if (bfe.weakKeyCheck())
		{
			System.out.println("ECB key is weak!");
		}
		else
		{
			System.out.println("ECB key OK");
		}

		if (bfc.weakKeyCheck())
		{
			System.out.println("CBC key is weak!");
		}
		else
		{
			System.out.println("CBC key OK");
		}

		// get a message

		System.out.print("something to encrypt please >");
		System.out.flush();

		tempBuf = new byte[MAX_MESS_SIZE];

		nMsgSize = 0;
		nLnBrkLen = 0;

		try
		{
			nLnBrkLen = System.getProperty("line.separator").length();
		}
		catch (Throwable err)
		{
		};

		try
		{
			// (cut off the line break)
			nMsgSize = System.in.read(tempBuf) - nLnBrkLen;
			cpyBuf = new byte[nMsgSize];
			System.arraycopy(tempBuf, 0, cpyBuf, 0, nMsgSize);
			tempBuf = cpyBuf;
		}
		catch (java.io.IOException ioe)
		{
			return;
		}

		// align to the next 8 byte border

		nRest = nMsgSize & 7;

		if (nRest != 0)
		{
			msgBuf = new byte[(nMsgSize & (~7)) + 8];

			System.arraycopy(tempBuf, 0, msgBuf, 0, nMsgSize);

			for (nI = nMsgSize; nI < msgBuf.length; nI++)
			{
				msgBuf[nI] = 0;
			}

			System.out.println(
				"message with "
					+ nMsgSize
					+ " bytes aligned to "
					+ msgBuf.length
					+ " bytes");
		}
		else
		{
			msgBuf = new byte[nMsgSize];

			System.arraycopy(tempBuf, 0, msgBuf, 0, nMsgSize);
		}

		System.out.println(
			"aligned data : " + BinConverter.bytesToHexStr(msgBuf));

		// ECB encryption/decryption test

		bfe.encrypt(msgBuf, 0, msgBuf, 0, msgBuf.length);

		// show the result

		System.out.println(
			"ECB encrypted: " + BinConverter.bytesToHexStr(msgBuf));

		bfe.decrypt(msgBuf, 0, msgBuf, 0, msgBuf.length);

		System.out.println("ECB decrypted: >>>" + new String(msgBuf) + "<<<");

		// CBC encryption/decryption test

		showIV = new byte[BlowfishCBC.BLOCKSIZE];

		bfc.getCBCIV(showIV, 0);

		System.out.println("CBC IV: " + BinConverter.bytesToHexStr(showIV));

		bfc.encrypt(msgBuf, 0, msgBuf, 0, msgBuf.length);

		// show the result

		System.out.println(
			"CBC encrypted: " + BinConverter.bytesToHexStr(msgBuf));

		bfc.setCBCIV(CBCIV_START);
		bfc.decrypt(msgBuf, 0, msgBuf, 0, msgBuf.length);

		System.out.println("CBC decrypted: >>>" + new String(msgBuf) + "<<<");

		System.out.println("tests done.");

		// demonstrate easy encryption

		bfes = new BlowfishEasy(BFEASY_REF_PASSW.toCharArray());

		System.out.println(sEnc = bfes.encryptString(BFEASY_REF_TEXT));
		System.out.println(bfes.decryptString(sEnc));

		// show stream handling

		try
		{
			bfos = new BlowfishOutputStream(
				XCHG_KEY,
				0,
				XCHG_KEY.length,
				baos = new ByteArrayOutputStream());

			for (nI = 0; nI < XCHG_DATA_SIZE; nI++)
			{
				bfos.write(nI);
			}

			bfos.close();

			tempBuf = baos.toByteArray();

			System.out.println(BinConverter.bytesToHexStr(tempBuf));

			bfis = new BlowfishInputStream(
				XCHG_KEY,
				0,
				XCHG_KEY.length,
				new ByteArrayInputStream(tempBuf));

			for (nI = 0; nI < XCHG_DATA_SIZE; nI++)
			{
				if ((nI & 0x0ff) != bfis.read())
				{
					System.out.println(
						"corrupted data at position " + nI);
				}
			}

			bfis.close();
		}
		catch (IOException ie)
		{
			System.out.println(ie);
		}

		// benchmark

		System.out.println("\nrunning benchmark (CBC)...");

		lTm = System.currentTimeMillis();

		tempBuf = new byte[TESTBUFSIZE];

		for (nI = 0; nI < TESTLOOPS; nI++)
		{
			bfc.encrypt(tempBuf, 0, tempBuf, 0, tempBuf.length);

			if (0 == (nI % (TESTLOOPS / 40)))
			{
				System.out.print("#");
				System.out.flush();
			}
		}

		lTm = System.currentTimeMillis() - lTm;

		System.out.println();

		dAmount = TESTBUFSIZE * TESTLOOPS;
		dTime = lTm;
		dRate = (dAmount * 1000) / dTime;
		lRate = (long) dRate;

		System.out.println(+ lRate + " bytes/sec");

		bfe.cleanUp();
		bfc.cleanUp();
	}

}
