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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.sourceforge.blowfishj.SHA1;

/**
  * Simple SHA-1 test application; note that the time this package was written
  * SHA-1 hashing wasn't included officially in the Java framework; in these
  * days it could actually be replaced by the MessageDigest factory's
  * capabilities.
  */
public class SHA1Demo
{
	/**
	 * Application entry point.
	 * @param args parameters
	 */
    public static void main(
    	String[] args)
    {
        int nI;
		byte[] tohash, dg0, dg1;
		net.sourceforge.blowfishj.SHA1 s;
        String sTest;


        s = new SHA1();

        System.out.print("running selftest...");

        if (!s.selfTest())
        {
            System.out.println(", FAILED");
            return;
        }

        System.out.println(", done.");

        sTest = (args.length > 0) ?
        	args[0] :
            "0123456789abcdefghijklmnopqrstuvwxyz";

        tohash = sTest.getBytes();
        s.update(tohash, 0, tohash.length);
        s.finalize();

        System.out.println("\"" + sTest + "\": " + s.toString());

        s.clear();

        // check against the standard ...

        s = new SHA1();

        tohash = new byte[257];
        for (nI = 0; nI < tohash.length; nI++) tohash[nI] = (byte)nI;

        s.update(tohash, 0, tohash.length);
        s.finalize();

        MessageDigest mds;

        try
        {
            mds = MessageDigest.getInstance("SHA");
        }
        catch (NoSuchAlgorithmException nsae)
        {
            System.out.println("standard SHA-1 not available");
            return;
        }

        mds.update(tohash);

        dg0 = s.getDigest();
        dg1 = mds.digest();

        for (nI = 0; nI < dg0.length; nI++)
        {
            if (dg0[nI] != dg1[nI])
            {
                System.out.println("NOT compatible to the standard!");
                return;
            }
        }

        System.out.println("compatibiliy test OK.");
    }
}
