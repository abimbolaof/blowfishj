
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Simple SHA-1 test application; note that the time this package was written
 * SHA-1 hashing wasn't included officially in the Java framework; in these
 * days it could actually be replaced by the MessageDigest factory's
 * capabilities.
 */
public class SHA1Demo {
    private static final byte[] SELFTEST_MESSAGE =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
    private static final byte[] SELFTEST_DIGEST =
            {
                    (byte) 0x84, (byte) 0x98, (byte) 0x3e, (byte) 0x44, (byte) 0x1c,
                    (byte) 0x3b, (byte) 0xd2, (byte) 0x6e, (byte) 0xba, (byte) 0xae,
                    (byte) 0x4a, (byte) 0xa1, (byte) 0xf9, (byte) 0x51, (byte) 0x29,
                    (byte) 0xe5, (byte) 0xe5, (byte) 0x46, (byte) 0x70, (byte) 0xf1
            };

    public static void main(
            String[] args) {


        SHA1 s = new SHA1();

        System.out.print("running selftest...");

        if (!selfTest()) {
            System.out.println(", FAILED");
            return;
        }

        System.out.println(", done.");

        String sTest = args.length > 0 ?
                args[0] :
                "0123456789abcdefghijklmnopqrstuvwxyz";

        byte[] tohash = sTest.getBytes();
        s.update(tohash, 0, tohash.length);
        s.finalize();

        System.out.println("\"" + sTest + "\": " + s);

        s.clear();

        // check against the standard ...

        s = new SHA1();

        tohash = new byte[257];
        int nI;
        for (nI = 0; nI < tohash.length; nI++) {
            tohash[nI] = (byte) nI;
        }

        s.update(tohash, 0, tohash.length);
        s.finalize();

        MessageDigest mds;

        try {
            mds = MessageDigest.getInstance("SHA");
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("standard SHA-1 not available");
            return;
        }

        mds.update(tohash);

        byte[] dg0 = s.getDigest();
        byte[] dg1 = mds.digest();

        for (nI = 0; nI < dg0.length; nI++) {
            if (dg0[nI] != dg1[nI]) {
                System.out.println("NOT compatible to the standard!");
                return;
            }
        }

        System.out.println("compatibiliy test OK.");
    }

    /**
     * Runs an integrity test.
     *
     * @return true: selftest passed / false: selftest failed
     */
    private static boolean selfTest() {


        SHA1 tester = new SHA1();

        tester.update(SELFTEST_MESSAGE, 0, SELFTEST_MESSAGE.length);
        tester.finalize();

        byte[] digest = tester.getDigest();

        for (int nI = 0; nI < SHA1.DIGEST_SIZE; nI++) {
            if (digest[nI] != SELFTEST_DIGEST[nI]) {
                return false;
            }
        }
        return true;
    }
}
