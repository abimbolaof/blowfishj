
/*
 * Copyright 2004 Markus Hahn 
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

package test.net.sourceforge.blowfishj;

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
