The OP2 compiler from System 3 Release 2.3.7 Alpha
Downloaded from https://sourceforge.net/projects/nativeoberon/files/nativeoberon/Native%20Oberon%202.3.7%20Alpha/NativeOberon2.3.7.tar.gz/download
Accessed 2025-07-11 

All files in the archive have a modification date of 2003-01-05

Changes
- Translated to utf-8 from native oberon format using ObxIDE
- Added stub modules to accommodate all references
- Removed Compiler.Mod and unnecessary system stubs, added OP2.Mod as stand-alone replacement
- Changed OPM so that error messages are in the module instead of loading from OP2.Errors
- Changed OPA so that it can parse source files with Unix endings too
- Refactored OPT, OPM and OPB, so that i386 no longer leaks into frontend, abstracted away into new OPTR
- Refactored OPC and OPL; OPC is now fully target independent; IR defs and data in new OPIR, no longer in OPL.
- Added ARMv7 backend compatible with Raspberry Pi Model 3b and Zero 2


The .Mod files can be transpiled to C99 files using the AoCodeNavigator; these files are
put into the c99 directory and built with build.sh. The resulting executable
runs on all platforms and generates x86 OP2 v2.3.7 object files compatible with
the Oberon System 3. Inline assembly is supported if the OPA.Data is in the same
directory as the compiler executable. This allows to cross-compile a full
Oberon System 3.

The bootlinker is a migration of the Oberon System BootLinker.Mod with a few additions
which make it useful for other projects than the Oberon System. It can generate a
Multiboot header and add stack initialization. With this, e.g. the MainLoop testcase 
together with the RawOut module work well on QEMU. Newer versions of the bootlinker
include multi-target support.

