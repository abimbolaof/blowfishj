
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

/**
 * Implementation of the Blowfish encryption algorithm in CBC mode.
 */
public class BlowfishCBC extends BlowfishECB
{

	// the CBC IV

	private int m_nIVLo;
	private int m_nIVHi;



	/**
	 * Gets the current CBC IV.
	 * @return current CBC IV
	 */
	public long getCBCIV()
	{
		return BinConverter.makeLong(m_nIVLo, m_nIVHi);
	}

	/**
	 * Gets a copy of the current CBC IV.
	 * @param dest buffer
	 * @param nOfs where to start writing
	 */
	public void getCBCIV(
		byte[] dest,
		int nOfs)
	{
		BinConverter.intToByteArray(m_nIVHi, dest, nOfs);
		BinConverter.intToByteArray(m_nIVLo, dest, nOfs + 4);
	}



	/**
	 * Sets the current CBC IV (for cipher resets).
	 * @param lNewCBCIV the new CBC IV
	 */
	public void setCBCIV(
		long lNewCBCIV)
	{
		m_nIVHi = BinConverter.longHi32(lNewCBCIV);
		m_nIVLo = BinConverter.longLo32(lNewCBCIV);
	}



	/**
	 * Sets the current CBC IV (for cipher resets).
	 * @param newCBCIV the new CBC IV
	 * @param nOfs where to start reading the IV
	 */
	public void setCBCIV(
		byte[] newCBCIV,
		int nOfs)
	{
		m_nIVHi = BinConverter.byteArrayToInt(newCBCIV, nOfs);
		m_nIVLo = BinConverter.byteArrayToInt(newCBCIV, nOfs + 4);
	}

	/**
	 * Constructor, uses a zero CBC IV.
	 * @param key key material, up to MAXKEYLENGTH bytes
	 * @param nOfs where to start reading the key
	 * @param nLen size of the key in bytes
	 */
	public BlowfishCBC(
		byte[] key,
		int nOfs,
		int nLen)
	{
		super(key, nOfs, nLen);

		m_nIVHi = m_nIVLo = 0;
	}


	/**
	 * Constructor to define the CBC IV.
	 * @param key key material, up to MAXKEYLENGTH bytes
	 * @param nOfs where to start reading the key
	 * @param nLen size of the key in bytes
	 * @param lInitCBCIV the CBC IV
	 */
	public BlowfishCBC(
		byte[] key,
		int nOfs,
		int nLen,
		long lInitCBCIV)
	{
		super(key, nOfs, nLen);

		setCBCIV(lInitCBCIV);
	}


	/**
	 * Constructor to define the CBC IV.
	 * @param key key material, up to MAXKEYLENGTH bytes
	 * @param nOfs where to start reading the key
	 * @param nLen size of the key in bytes
	 * @param initCBCIV the CBC IV
	 * @param nIVOfs where to start reading the IV
	 */
	public BlowfishCBC(
		byte[] key,
		int nOfs,
		int nLen,
		byte[] initCBCIV,
		int nIVOfs)
	{
		super(key, nOfs, nLen);

		setCBCIV(initCBCIV, nIVOfs);
	}



	/**
	 * see net.sourceforge.blowfishj.BlowfishECB#cleanUp()
	 */
	public void cleanUp()
	{
		m_nIVHi = m_nIVLo = 0;
		super.cleanUp();
	}


    /**
     * @see BlowfishECB#encrypt(byte[], int, byte[], int, int)
     */
    public int encrypt(
            byte[] inBuf,
            int nInPos,
            byte[] outBuf,
            int nOutPos,
            int nLen) {
        // same speed tricks than in the ECB variant ...

        nLen -= nLen % BLOCKSIZE;

        int nInPos1 = nInPos;
        int nC = nInPos1 + nLen;

        int[] pbox = this.getPbox();
        int nPBox00 = pbox[0];
        int nPBox01 = pbox[1];
        int nPBox02 = pbox[2];
        int nPBox03 = pbox[3];
        int nPBox04 = pbox[4];
        int nPBox05 = pbox[5];
        int nPBox06 = pbox[6];
        int nPBox07 = pbox[7];
        int nPBox08 = pbox[8];
        int nPBox09 = pbox[9];
        int nPBox10 = pbox[10];
        int nPBox11 = pbox[11];
        int nPBox12 = pbox[12];
        int nPBox13 = pbox[13];
        int nPBox14 = pbox[14];
        int nPBox15 = pbox[15];
        int nPBox16 = pbox[16];
        int nPBox17 = pbox[17];

        int[] sbox1 = this.getSbox1();
        int[] sbox2 = this.getSbox2();
        int[] sbox3 = this.getSbox3();
        int[] sbox4 = this.getSbox4();

        int nIVHi = m_nIVHi;
        int nIVLo = m_nIVLo;

        int nOutPos1 = nOutPos;
        while (nInPos1 < nC) {
            int nHi = inBuf[nInPos1++] << 24;
            nHi |= inBuf[nInPos1++] << 16 & 0x0ff0000;
            nHi |= inBuf[nInPos1++] << 8 & 0x000ff00;
            nHi |= inBuf[nInPos1++] & 0x00000ff;

            int nLo = inBuf[nInPos1++] << 24;
            nLo |= inBuf[nInPos1++] << 16 & 0x0ff0000;
            nLo |= inBuf[nInPos1++] << 8 & 0x000ff00;
            nLo |= inBuf[nInPos1++] & 0x00000ff;

            // extra step: chain with IV

            nHi ^= nIVHi;
            nLo ^= nIVLo;

            nHi ^= nPBox00;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox01;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox02;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox03;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox04;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox05;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox06;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox07;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox08;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox09;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox10;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox11;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox12;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox13;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox14;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox15;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox16;

            nLo ^= nPBox17;

            outBuf[nOutPos1++] = (byte) (nLo >>> 24);
            outBuf[nOutPos1++] = (byte) (nLo >>> 16);
            outBuf[nOutPos1++] = (byte) (nLo >>> 8);
            outBuf[nOutPos1++] = (byte) nLo;

            outBuf[nOutPos1++] = (byte) (nHi >>> 24);
            outBuf[nOutPos1++] = (byte) (nHi >>> 16);
            outBuf[nOutPos1++] = (byte) (nHi >>> 8);
            outBuf[nOutPos1] = (byte) nHi;
            nOutPos1++;

            // (the encrypted block becomes the new IV)

            nIVHi = nLo;
            nIVLo = nHi;
        }

        m_nIVHi = nIVHi;
        m_nIVLo = nIVLo;

        return nLen;
    }

    /**
     * @see BlowfishECB#encrypt(int[], int, int[], int, int)
     */
    public void encrypt(
            int[] inBuf,
            int nInPos,
            int[] outBuf,
            int nOutPos,
            int nLen) {
        int nInPos1 = nInPos;
        int nOutPos1 = nOutPos;
        int nC = nInPos1 + nLen;

        while (nInPos1 < nC) {
            BinConverter.intToByteArray(inBuf[nInPos1++], blockBuf, 0);
            BinConverter.intToByteArray(inBuf[nInPos1++], blockBuf, 4);

            encrypt(blockBuf, 0, blockBuf, 0, blockBuf.length);

            outBuf[nOutPos1++] = BinConverter.byteArrayToInt(blockBuf, 0);
            outBuf[nOutPos1] = BinConverter.byteArrayToInt(blockBuf, 4);
            nOutPos1++;
        }
    }

    /**
     * @see BlowfishECB#encrypt(long[], int, long[], int, int)
     */
    public void encrypt(
            long[] inBuf,
            int nInPos,
            long[] outBuf,
            int nOutPos,
            int nLen) {
        int nInPos1 = nInPos;
        int nOutPos1 = nOutPos;
        int nC = nInPos1 + nLen;

        while (nInPos1 < nC) {
            BinConverter.longToByteArray(inBuf[nInPos1++], blockBuf, 0);

            encrypt(blockBuf, 0, blockBuf, 0, blockBuf.length);

            outBuf[nOutPos1] = BinConverter.byteArrayToInt(blockBuf, 0);
            nOutPos1++;
        }
    }

    /**
     * @see BlowfishECB#decrypt(byte[], int, byte[], int, int)
     */
    public int decrypt(
            byte[] inBuf,
            int nInPos,
            byte[] outBuf,
            int nOutPos,
            int nLen) {
        nLen -= nLen % BLOCKSIZE;

        int nInPos1 = nInPos;
        int nC = nInPos1 + nLen;

        int[] pbox = this.getPbox();
        int nPBox00 = pbox[0];
        int nPBox01 = pbox[1];
        int nPBox02 = pbox[2];
        int nPBox03 = pbox[3];
        int nPBox04 = pbox[4];
        int nPBox05 = pbox[5];
        int nPBox06 = pbox[6];
        int nPBox07 = pbox[7];
        int nPBox08 = pbox[8];
        int nPBox09 = pbox[9];
        int nPBox10 = pbox[10];
        int nPBox11 = pbox[11];
        int nPBox12 = pbox[12];
        int nPBox13 = pbox[13];
        int nPBox14 = pbox[14];
        int nPBox15 = pbox[15];
        int nPBox16 = pbox[16];
        int nPBox17 = pbox[17];

        int[] sbox1 = this.getSbox1();
        int[] sbox2 = this.getSbox2();
        int[] sbox3 = this.getSbox3();
        int[] sbox4 = this.getSbox4();

        int nIVHi = m_nIVHi;
        int nIVLo = m_nIVLo;

        int nOutPos1 = nOutPos;
        while (nInPos1 < nC) {
            int nHi = inBuf[nInPos1++] << 24;
            nHi |= inBuf[nInPos1++] << 16 & 0x0ff0000;
            nHi |= inBuf[nInPos1++] << 8 & 0x000ff00;
            nHi |= inBuf[nInPos1++] & 0x00000ff;

            int nLo = inBuf[nInPos1++] << 24;
            nLo |= inBuf[nInPos1++] << 16 & 0x0ff0000;
            nLo |= inBuf[nInPos1++] << 8 & 0x000ff00;
            nLo |= inBuf[nInPos1++] & 0x00000ff;

            // (save the current block, it will become the new IV)
            int nTmpHi = nHi;
            int nTmpLo = nLo;

            nHi ^= nPBox17;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox16;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox15;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox14;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox13;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox12;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox11;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox10;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox09;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox08;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox07;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox06;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox05;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox04;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox03;
            nLo ^= (sbox1[nHi >>> 24] + sbox2[nHi >>> 16 & 0x0ff] ^ sbox3[nHi >>> 8 & 0x0ff]) + sbox4[nHi & 0x0ff] ^ nPBox02;
            nHi ^= (sbox1[nLo >>> 24] + sbox2[nLo >>> 16 & 0x0ff] ^ sbox3[nLo >>> 8 & 0x0ff]) + sbox4[nLo & 0x0ff] ^ nPBox01;

            nLo ^= nPBox00;

            // extra step: unchain

            nHi ^= nIVLo;
            nLo ^= nIVHi;

            outBuf[nOutPos1++] = (byte) (nLo >>> 24);
            outBuf[nOutPos1++] = (byte) (nLo >>> 16);
            outBuf[nOutPos1++] = (byte) (nLo >>> 8);
            outBuf[nOutPos1++] = (byte) nLo;

            outBuf[nOutPos1++] = (byte) (nHi >>> 24);
            outBuf[nOutPos1++] = (byte) (nHi >>> 16);
            outBuf[nOutPos1++] = (byte) (nHi >>> 8);
            outBuf[nOutPos1] = (byte) nHi;
            nOutPos1++;

            // (now set the new IV)
            nIVHi = nTmpHi;
            nIVLo = nTmpLo;
        }

        m_nIVHi = nIVHi;
        m_nIVLo = nIVLo;

        return nLen;
    }

    /**
     * @see BlowfishECB#decrypt(int[], int, int[], int, int)
     */
    public void decrypt(
            int[] inBuf,
            int nInPos,
            int[] outBuf,
            int nOutPos,
            int nLen) {
        int nInPos1 = nInPos;
        int nOutPos1 = nOutPos;
        int nC = nInPos1 + nLen;

        while (nInPos1 < nC) {
            BinConverter.intToByteArray(inBuf[nInPos1++], blockBuf, 0);
            BinConverter.intToByteArray(inBuf[nInPos1++], blockBuf, 4);

            decrypt(blockBuf, 0, blockBuf, 0, blockBuf.length);

            outBuf[nOutPos1++] = BinConverter.byteArrayToInt(blockBuf, 0);
            outBuf[nOutPos1] = BinConverter.byteArrayToInt(blockBuf, 4);
            nOutPos1++;
        }
    }

    /**
     * @see BlowfishECB#decrypt(long[], int, long[], int, int)
     */
    public void decrypt(
            long[] inBuf,
            int nInPos,
            long[] outBuf,
            int nOutPos,
            int nLen) {
        int nInPos1 = nInPos;
        int nOutPos1 = nOutPos;
        int nC = nInPos1 + nLen;

        while (nInPos1 < nC) {
            BinConverter.longToByteArray(inBuf[nInPos1++], blockBuf, 0);

            decrypt(blockBuf, 0, blockBuf, 0, blockBuf.length);

            outBuf[nOutPos1] = BinConverter.byteArrayToInt(blockBuf, 0);
            nOutPos1++;
        }
    }

}
