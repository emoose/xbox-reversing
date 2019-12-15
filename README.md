Collection of things to help with reversing that I've made or come across, hopefully others might find these useful!

Feel free to make an issue/PR if you have any problems or improvements.

## Contents

### xbox360.py & x360_imports.py
IDA 7.0+ python loader script for Xbox360 XEX executables, should support loading almost all (uncompressed) XEX formats, including most pre-1888 beta formats.

To make use of it copy both scripts into your IDA loaders/ directory, and make sure your Python2.7 setup has PyCrypto module installed ("pip install pycrypto"...)

This almost has feature-parity with xorloser's excellent Xex Loader, though sadly is missing two major features in comparison:
- compressed XEX support: requires an LZX decompressor, doesn't seem to be any native Python2.7 impl. available though (really should have checked before starting this!)
- adding to imports window: while we can read & map in all imports from a module fine, there strangely doesn't seem to be any Python API for populating the imports window :(

Since those have pretty major blockers I don't think any more development will be happening to this script, hopefully it might come in handy for anyone wanting to write a proper IDA/Ghidra plugin though :)

### templates/
This folder contains templates for use with [010 Editor](https://www.sweetscape.com/010editor/). Xbox360 related templates were mainly written by Anthony, with some very minor additions by me.

Templates can be installed by opening Options -> Compiling -> Templates, clicking "Add..." and then choosing the template to install, which should make 010 Editor automatically load the template when opening a supported file.

## License
All code is licensed under the 3-Clause BSD License unless otherwise stated.
