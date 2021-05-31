Collection of things to help with reversing that I've made or come across, hopefully others might find these useful!

Feel free to make an issue/PR if you notice any issues/have any problems/find any improvements.

## Contents

### [stfschk](https://github.com/emoose/xbox-reversing/tree/master/stfschk)
Allows verifying the hashes & signature of an Xbox360 STFS package (LIVE/PIRS/CON...), Arcade games and demos are usually stored in this format, sometimes prototypes have been found stored in STFS containers too, stfschk can help you know if the data you have is valid or not.

More info can be found in the stfschk [README.md](https://github.com/emoose/xbox-reversing/blob/master/stfschk/README.md), the STFS format is also described in my [Xbox360Container.bt](https://github.com/emoose/xbox-reversing/blob/master/templates/Xbox360Container.bt) template, Free60 also has some good info on the format here: https://free60project.github.io/wiki/STFS/

### [xbox360.py](https://github.com/emoose/xbox-reversing/blob/master/xbox360.py) & [x360_imports.py](https://github.com/emoose/xbox-reversing/blob/master/x360_imports.py)
**(Note: an updated, native DLL version of xbox360.py can be found here: https://github.com/emoose/idaxex)**

IDA 7.0+ python loader script for Xbox360 XEX executables, should support loading almost all (uncompressed) XEX formats, including most pre-1888 beta formats.

To make use of it copy both scripts into your IDA loaders/ directory, and make sure your Python2.7 setup has PyCrypto module installed ("pip install pycrypto"...)

This almost has feature-parity with xorloser's excellent Xex Loader, though sadly is missing two major features in comparison:
- compressed XEX support: requires an LZX decompressor, doesn't seem to be any native Python2.7 impl. available though (really should have checked before starting this!)
- adding to imports window: while we can read & map in all imports from a module fine, there strangely doesn't seem to be any Python API for populating the imports window :(

Since those have pretty major blockers I don't think any more development will be happening to this script, hopefully it might come in handy for anyone wanting to write a proper IDA/Ghidra plugin though :)

### [templates/](https://github.com/emoose/xbox-reversing/tree/master/templates)
This folder contains templates for use with [010 Editor](https://www.sweetscape.com/010editor/). Xbox360 related templates were mainly written by Anthony, with some very minor additions by me.

Templates can be installed by opening Options -> Compiling -> Templates, clicking "Add..." and then choosing the template to install, which should make 010 Editor automatically load the template when opening a supported file.

## License
All code is licensed under the 3-Clause BSD License unless otherwise stated.
