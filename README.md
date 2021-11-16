
  Welcome to 'aud', a linux file system auditing tool. It builds
  itself with sha256's for files of interest and will then audit them
  for change. It is rather paranoid as it preforms sha256 checks on its
  own .text instruction stream as well as the file list data table.

  'aud' can also be used during package install to make sure all
   files ended up where they are supposed to be and with the
   correct protection codes.
   
Build Instructions

  First, edit aud.txt with files you wish to audit.

  Then,
      make

  You will end up with 'aud', an audit program. Place that somewhere
  like /usr/local/bin.

  Keep the source files around, but with restricted access, as you may
  from time to time, need to rebuild aud.

To Run

  ./aud

  You can also run 'aud' from a script of some sort. It returns a 0 if it
  was a clean run, else *errors<<16 | 1) is returned.

  Note that any errors are logged in /var/log/auth.log.

To Test

  After install

      make test

  And no errors should be generated.
  
Under The Hood

  'aud' first uses sha256 to verify the data table that was built from aud.txt.
  Next, it uses sha256 to audit its own .text (ie machine code instructions) segment.

  An audit error will be generated if LD_PRELOAD is set. The last thing you want is
  for a malicious user to override your libraries.

  An audit error will be generated if the kernel version has changed. See the third
  field printed from 'uname -a' and compare this with audtab.h if you get this error.

  'aud' will walk down the list of files you placed in aud.txt, AND it will
  extract any libraries these executables link with and audit those as well.
  For example, if you had placed /usr/bin/python3 in aud.txt, 'aud' would
  audit this list as well:

  linex-vdso.so.1 is a special case. It resolves to /lib/modules/<kernel>/vdso/vs*
  with each of these files being audited.

  Note that in addition to checking the file with sha256, 'aud' ALSO checks
  the stat() of the file. This is done to watch for any changed in protection
  codes.
  
Notes

1. Deep in the bowels of library chains, there are a few libraries that
   can't be found without defining LD_LIBRARY_PATH. Even worse, there are
   some libraries that don't exist period on the hard drive. None of these errors
   are broken out, but should they be?

2. Some applications, using dlopen, dlsym, and dlclose can override the automatic
   binding by the loader. None of this is audited. Perhaps a dummy library can
   be built and forced in with LD_PRELOAD to make sure that these calls aren't made.
   Also, none of the dlopen et all environmental variables are audited.

   If you want to check that none of your programs secretly call dlopen,
   first do a make -f Makefile.dl, then set LD_PRELOAD=dlcheck.so, rhwn
   run your program. The library OVERRIDES the dlopen routine in libc and
   will display an error if called.
   
3. Sometimes, aud won't build the proper .text checksums. You can troubleshoot
   this by running it with the -z flag. It will display the .text section then
   exit. Just diff this output with a previous run to see the .text differences.
   Strangely, there is some sort of checksum in the .text section that watches
   after the .data section. Dig into elf for the reason. See .hash in the
   text region of aud.map.

4. aud.dat can not contain /usr/local/bin/aud. That is to say, the system
   won't audit itself. However, remember that aud does internal audits
   at startup of it's data tables and it's .text space so it gives you
   some assurance that it hasn't been mucked with.
   