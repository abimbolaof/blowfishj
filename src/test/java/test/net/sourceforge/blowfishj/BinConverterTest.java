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

import junit.framework.TestCase;
import net.sourceforge.blowfishj.BinConverter;

/**
 * Test cases for the binary converters.
 */
public class BinConverterTest extends TestCase
{
	final public void testByteArrayToInt()
	{
		byte[] dat =
		{
			(byte)0x00, (byte)0xcc, (byte)0xaf, (byte)0x43, (byte)0x1e
		};

		assertTrue(0x00ccaf43 == BinConverter.byteArrayToInt(dat, 0));
		assertTrue(0xccaf431e == BinConverter.byteArrayToInt(dat, 1));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testIntToByteArray()
	{
		byte[] testb = new byte[5];

		BinConverter.intToByteArray(0x01234567, testb, 0);

		assertTrue(0x01 == testb[0]);
		assertTrue(0x23 == testb[1]);
		assertTrue(0x45 == testb[2]);
		assertTrue(0x67 == testb[3]);

		BinConverter.intToByteArray(0x89abcdef, testb, 1);

		assertTrue((byte)0x89 == testb[1]);
		assertTrue((byte)0xab == testb[2]);
		assertTrue((byte)0xcd == testb[3]);
		assertTrue((byte)0xef == testb[4]);
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testByteArrayToLong()
	{
		byte[] dat =
		{
			(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
			(byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
			(byte)0xcc
		};

		assertTrue(0x0123456789abcdefL == BinConverter.byteArrayToLong(dat, 0));
		assertTrue(0x23456789abcdefccL == BinConverter.byteArrayToLong(dat, 1));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testLongToByteArray()
	{
		byte[] testb = new byte[9];

		BinConverter.longToByteArray(0x0123456789abcdefL, testb, 0);

		assertTrue((byte)0x01 == testb[0]);
		assertTrue((byte)0x23 == testb[1]);
		assertTrue((byte)0x45 == testb[2]);
		assertTrue((byte)0x67 == testb[3]);
		assertTrue((byte)0x89 == testb[4]);
		assertTrue((byte)0xab == testb[5]);
		assertTrue((byte)0xcd == testb[6]);
		assertTrue((byte)0xef == testb[7]);

		BinConverter.longToByteArray(0x0123456789abcdefL, testb, 1);

		assertTrue((byte)0x01 == testb[1]);
		assertTrue((byte)0x23 == testb[2]);
		assertTrue((byte)0x45 == testb[3]);
		assertTrue((byte)0x67 == testb[4]);
		assertTrue((byte)0x89 == testb[5]);
		assertTrue((byte)0xab == testb[6]);
		assertTrue((byte)0xcd == testb[7]);
		assertTrue((byte)0xef == testb[8]);
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testIntArrayToLong()
	{
		int[] dat =
		{
			0x01234567, 0x89abcdef, 0xcc01aa02
		};

		assertTrue(0x0123456789abcdefL == BinConverter.intArrayToLong(dat, 0));
		assertTrue(0x89abcdefcc01aa02L == BinConverter.intArrayToLong(dat, 1));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testLongToIntArray()
	{
		int[] testn = new int[3];

		BinConverter.longToIntArray(0x0123456789abcdefL, testn, 0);

		assertTrue(0x01234567 == testn[0]);
		assertTrue(0x89abcdef == testn[1]);

		BinConverter.longToIntArray(0x0123456789abcdefL, testn, 1);

		assertTrue(0x01234567 == testn[1]);
		assertTrue(0x89abcdef == testn[2]);
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testMakeLong()
	{
		assertTrue(0x0123456789abcdefL ==
			BinConverter.makeLong(0x89abcdef, 0x01234567));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testLongLo32()
	{
		assertTrue(0x89abcdef == BinConverter.longLo32(0x0123456789abcdefL));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testLongHi32()
	{
		assertTrue(0x01234567 == BinConverter.longHi32(0x0123456789abcdefL));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testBytesToHexStr()
	{
		byte[] dat =
		{
			(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
			(byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
		};

		String sHex = "0123456789abcdef";

		assertTrue(sHex.equals(BinConverter.bytesToHexStr(dat)));

		sHex = "456789abcd";

		assertTrue(sHex.equals(BinConverter.bytesToHexStr(dat, 2, 5)));
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testhexStrToBytes()
	{
		byte[] testb = new byte[9];

		BinConverter.hexStrToBytes("0123456789abcdef", testb, 0, 0, 8);

		assertTrue((byte)0x01 == testb[0]);
		assertTrue((byte)0x23 == testb[1]);
		assertTrue((byte)0x45 == testb[2]);
		assertTrue((byte)0x67 == testb[3]);
		assertTrue((byte)0x89 == testb[4]);
		assertTrue((byte)0xab == testb[5]);
		assertTrue((byte)0xcd == testb[6]);
		assertTrue((byte)0xef == testb[7]);

		BinConverter.hexStrToBytes("0123456789abcdef", testb, 4, 1, 5);

		assertTrue((byte)0x45 == testb[1]);
		assertTrue((byte)0x67 == testb[2]);
		assertTrue((byte)0x89 == testb[3]);
		assertTrue((byte)0xab == testb[4]);
		assertTrue((byte)0xcd == testb[5]);
	}

	///////////////////////////////////////////////////////////////////////////

	final public void testByteArrayToStr()
	{
		byte[] testb = new byte[52];

		for (int nI = 0; nI < testb.length; nI += 2)
		{
			testb[nI    ] = 0;
			testb[nI + 1] = (byte)(0x061 + (nI >> 1));

		}

		assertTrue(BinConverter.byteArrayToStr(testb, 0, testb.length)
			.equals("abcdefghijklmnopqrstuvwxyz"));
	}
}
