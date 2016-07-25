
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

/**
 * Demonstrating the Blowfish encryption algorithm classes.
 */
public class BlowfishDemo
{
	// max. size of message to encrypt

	private static final int MAX_MESS_SIZE = 64;

	// benchmark settings

	private static final int TESTBUFSIZE = 100000;
	private static final int TESTLOOPS = 10000;

	// BlowfishEasy reference

	private static final String BFEASY_REF_PASSW = "secret";
	private static final String BFEASY_REF_TEXT = "Protect me.";

	// startup CBC IV

	private static final long CBCIV_START = 0x0102030405060708L;

	// things necessary for compatibility testing

	private static final byte[] XCHG_KEY =
	{
		(byte)0xaa, (byte)0xbb, (byte)0xcc, 0x00, 0x42, 0x33
	};
	private static final int XCHG_DATA_SIZE = 111;


	/**
	 * the application entry point
	 * @param args (command line) parameters
	 */
	public static void main(
			String[] args)
	{

		// create our test key

		byte[] testKey = new byte[5];
		int nI;
		for (nI = 0; nI < testKey.length; nI++)
		{
			testKey[nI] = (byte) (nI + 1);
		}

		// do the key setups and check for weaknesses

		System.out.print("setting up Blowfish keys...");

		BlowfishECB bfe = new BlowfishECB(testKey, 0, testKey.length);

		BlowfishCBC bfc = new BlowfishCBC(
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

		byte[] tempBuf = new byte[MAX_MESS_SIZE];

		int nMsgSize = 0;
		int nLnBrkLen = 0;

		try
		{
			nLnBrkLen = System.getProperty("line.separator").length();
		}
		catch (Throwable err)
		{
		    // nothing to do
		}

		try
		{
			// (cut off the line break)
			nMsgSize = System.in.read(tempBuf) - nLnBrkLen;
			byte[] cpyBuf = new byte[nMsgSize];
			System.arraycopy(tempBuf, 0, cpyBuf, 0, nMsgSize);
			tempBuf = cpyBuf;
		}
		catch (IOException ioe)
		{
			return;
		}

		// align to the next 8 byte border

		int nRest = nMsgSize & 7;

		byte[] msgBuf;
		if (nRest == 0) {
			msgBuf = new byte[nMsgSize];

			System.arraycopy(tempBuf, 0, msgBuf, 0, nMsgSize);
		} else {
			msgBuf = new byte[(nMsgSize & ~7) + 8];

			System.arraycopy(tempBuf, 0, msgBuf, 0, nMsgSize);

			for (nI = nMsgSize; nI < msgBuf.length; nI++) {
				// pad with spaces; zeros are a better solution when you need
				// to actually strip of the padding data later on (in our case
				// it wouldn't be printable though)
				msgBuf[nI] = ' ';
			}

			System.out.println(
					"message with "
							+ nMsgSize
							+ " bytes aligned to "
							+ msgBuf.length
							+ " bytes");
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

		byte[] showIV = new byte[BlowfishCBC.BLOCKSIZE];

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

		BlowfishEasy bfes = new BlowfishEasy(BFEASY_REF_PASSW.toCharArray());

		String sEnc;
		System.out.println(sEnc = bfes.encryptString(BFEASY_REF_TEXT));
		System.out.println(bfes.decryptString(sEnc));

		// show stream handling

		try
		{
			ByteArrayOutputStream baos;
			BlowfishOutputStream bfos = new BlowfishOutputStream(
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

			BlowfishInputStream bfis = new BlowfishInputStream(
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
			ie.printStackTrace();
		}

		// benchmark

		System.out.println("\nrunning benchmark (CBC)...");

		long lTm = System.currentTimeMillis();

		tempBuf = new byte[TESTBUFSIZE];

		for (nI = 0; nI < TESTLOOPS; nI++)
		{
			bfc.encrypt(tempBuf, 0, tempBuf, 0, tempBuf.length);

			if (nI % (TESTLOOPS / 40) == 0)
			{
				System.out.print("#");
				System.out.flush();
			}
		}

		lTm = System.currentTimeMillis() - lTm;

		System.out.println();

		double dAmount = TESTBUFSIZE * TESTLOOPS;
		double dTime = lTm;
		double dRate = dAmount * 1000 / dTime;
		long lRate = (long) dRate;

		System.out.println(+ lRate + " bytes/sec");

		bfe.cleanUp();
		bfc.cleanUp();
	}

}
