@echo off
REM batch file to create a classic ZIP file for distribution on <http://www.hotpixel.net/software.html>
REM * usage: classic.bat {3-digit-version}
REM * make sure to have md5cksum.exe in your path
REM * ZIP file gets created in the system's temporary folder
REM * old ZIP file(s) will be deleted
del %TEMP%\bfj%1.zip
zip -9 %TEMP%\bfj%1.zip src\java\net\sourceforge\blowfishj\*.java src\test\java\test\net\sourceforge\blowfishj\*.java license.txt readme.txt
md5cksum %TEMP%\bfj%1.zip