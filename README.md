Android backup extractor
========================
Utility to extract and repack Android backups created with ```adb backup``` (ICS+). 
Largely based on BackupManagerService.java from AOSP. 

Usage: 

Download the latest version of Bouncy Castle Provider jar 
(```bcprov-jdk15on-150.jar```) from here:

http://www.bouncycastle.org/latest_releases.html

Drop the latest Bouncy Castle jar in lib/, import in Eclipse and adjust 
build path if necessary.
Syntax: 

	usage: usage: abe [-h] [-v] -u | -p | -k   -b <arg> -t <arg> [-w <arg>] [-d]

	 -h,--help             display help message
	 -v,--version          display version

	 -u,--unpack           unpack given backup.ab file
	 -p,--pack             pack given tar file
	 -k,--packkk           pack given tar file to backup file with version 2 backup, compatible with Android 4.4.3
	 -b,--backup <arg>     backup file to unpack
	 -t,--archive <arg>    select output archive (tar) file
	 -w,--password <arg>   select password for unpack/pack operation
	 -d,--debug            be more verbose

If you don't specify a password the backup archive won't be encrypted but 
only compressed. 

Alternatively: 

Use the bundled Ant script to create an all-in-one jar and run with: 
(you still need to put the Bouncy Castle jar in lib/; modify the 
```bcprov.jar``` property accordingly)

```java -jar abe.jar [parameters as above]```

(Thanks to Jan Peter Stotz for contributing the build.xml file)

More details about the backup format and the tool implementation in the 
associated blog post: 

http://nelenkov.blogspot.com/2012/06/unpacking-android-backups.html
