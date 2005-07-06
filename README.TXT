 
BlowfishJ v2.15 (07/05/2005)


WHAT IS BLOWFISHJ?

This is my own implementation of the Blowfish encryption algorithm in ECB and
CBC mode. It's a simple to use package and runs at an excellent speed, around
40 Mb/s with the Hotspot Server VM of the JDK 1.4 on a P4/1700. The code
actually comes very close to the limits what is possible with Java. The latest
JDK it was tested on is 1.4.2_05-b04. Stream and string encryption solutions
are compatible to Blowfish.NET (a C# implementation), allowing an easy data
exchange between Java and the Microsoft.NET platform.

Next to the original sources this software also includes streaming classes
originally contributed by Dale Anson <danson@germane-software.com>.

For one of the real world application using BlowfishJ please check out John's
Zaurus JCryptPad at 

    http://www.wallacesoftware.com/zaurus/
    
Thanks to Siegfried Goeschl <siegfried.goeschl@it20one.at> BlowfishJ became an
official project at Sourceforge and is buildable via Maven/Ant. You can find
our project at:

    http://blowfishj.sf.net/

 
COPYRIGHT AND WARRANTY

This software is open source, which means that you can use it in your own
applets and applications without any license fees. The license model chosen is 
the Apache License 2.0, for more information check out the file LICENSE.TXT.
Additionally to that it would be appreciated that the usage is mentioned
somewhere in the documentation and that feedback is sent back to the author,
yet both is optional and not a must.


VERSION HISTORY 

2.15

- removed unused local variables, which were detected by the JDK 1.5 compiler
- some copyright/comment and demo code adjustments
- verified to compile and run in the new Eclipse 3.1 IDE

2.14

- root package names changed to (test.)net.sourceforge.blowfishj
- project is now hosted at Sourceforge, see above
- updated to Apache License 2.0
- added Maven build

2.13

- fixed a bug in the key setup of BlowfishECB, if keys were passed with an
  offset and they were smaller than Blowfish.BLOCKSIZE then the overall 56 byte
  key used was wrongfully assembled; a test case was added to prove the fix

2.12

- switch to Apache/BSD license (BlowfishJ is now a candidate for Jakarta)
- deprecated constructor in BlowfishSimple, introduced a better solution using
  the full Unicode data (be aware that the constructors are _not_ compatible!)
- added known weak key test
- added demo code for BlowfishEasy
- added compatibility tests for data exchange with Blowfish.NET
- removed the C++ sources (this project fell behind its expectations)

2.11

- added comments for each deprecated item
- added BUILD.BAT for auto-generation of docs, jar and class files (Win32 only)
- some bugs in the Javadoc comments

2.10

- instances (of ECB and CBC) can be reused by invoking initialize()
- added a JUnit test suite
- renamed BlowfishTest to BlowfishTest) and moved it to the test package
- moved InOutputStreamTest to the test package
- renamed SHA1Test to SHA1Demo and moved it to the test package 
- changed the benchmark to CBC/bytes encryption (closer to the real world)
- refactored the streams (e.g. deprecated the string consuming ctors)
- problem with streams: zero length content generated incompatible output
- bug with input stream: IV reading could fail for no reason
- renamed some methods in BinConverter (their names simply didn't make sense)
- general code cleanup and some minor speedups (yet outside of the hot spots)

2.02

- added Eclipse 2.1 project files
- removed deprecated method calls and obsolete imports
- reformatted all Java source code (e.g. to fit print margins)
- BlowfishJ is now published under the LGPL

2.01

- problem BlowfishCBC, only the first block got decrypted (wrong block swaps)
- BinConverter.binHexToBytes was flawed

2.00

- speed optimized the byte array handling methods (since they are the most
  commonly used), which gained around 50% more performance(!); both ECB and CBC
  classes now have separated inner loops for maximum speed
- all methods with array parameters have now new versions with offset and
  length parameters (where necessary), solves lots of data copying overhead for
  the caller
- also deprecated all of these old methods with array parameters
- extended and cleaned up BinConverter
- BlowfishEasy is now using the standard Java SHA-1 implementation
- fixed message input in BlowfishTest (length adjustment)

1.86

- added BlowfishJ implementation in C++
- decryption was referencing the box members, not the references on the stack,
  which lead to a decrease in performance

1.85

(first entry)


--
Copyright (c) 1997-2005 Markus Hahn <mhahn@cruzio.com>
