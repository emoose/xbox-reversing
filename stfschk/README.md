# stfschk

stfschk is an STFS filesystem checker/verifier, used to check the validity of Xbox 360 XContent packages.

By design STFS was made to allow verification of the file contents, where each 4096-byte part is hashed seperately into one of the many hash tables stored throughout the file.  
Hash table data also gets hashed into higher-level hash tables, with the top-level hash-table hash stored inside the files header.  
An RSA signature is then made of this header, either signed by Microsoft, an Xbox360 console, or an SDK (devkit) key.

stfschk allows the verification of this data, along with making sure file entries & metadata looks valid.

### Compatibility
Support is included only for XContent packages right now - while STFS is also used inside PEC & STFC cache partitions, neither of those are currently supported by this tool.  
The backend STFS code is based on [xbox-winfsp](https://github.com/emoose/xbox-winfsp) which does support those extra formats however, so adding support for them probably wouldn't be too difficult.

As the xbox-winfsp code was made to be read-only this only allows for passive checking of a file, repair attempts are out-of-scope of this tool.  
(it'd probably be better to just extract whatever contents you can and create a new package with them instead - again, out-of-scope of this, but there's many other tools out there that can do this)

### Usage
```
Usage:
  stfschk.exe <path\to\package.file>

Batch mode:
  stfschk.exe <path\to\folder>

Batch mode checks all packages in a folder, creating a <filename>.bad file for packages detected as bad
The .bad file contains info about why the file was marked as bad
Only files with valid XContent magic signature CON/LIVE/PIRS are checked when using batch mode
```

Alternatively, drag & drop an STFS file into the stfschk.exe.

### Scans
stfschk supports verification of the following:

- metadata hash (aka "content ID")
- hash tables/blocks
- data blocks
- directory entries (checks that block counts are valid & sane, and the block-chain looks valid)
- package size (checks for truncation & extra unused bytes)
- metadata values (currently only content size)

The result of these checks should give you a reasonable idea of the validity of a package.  
More checks (eg. header signature, to verify where the package originated from) will hopefully be added later on.

### Example output
An example summary provided by stfschk, from a file that had ~60% of the contents deleted:

```
Summary (invalid/total):
  Metadata hash: valid
  Hash tables: 741/1330
  Data blocks: 130/224430 (bad hash tables prevents checking data blocks, the invalid count may be higher!)
  Directory entries: 705/1601
  Block indices: 0/224430
  Package size: 0x185A674D (expected 0x371EB000, -516180147 bytes difference)
  (file truncated, too small to hold 225760 backing blocks)
  Expected path: 0000000000000000\58410931\000D0000\A7603793FD5268F4CDA9EC80D1921F0F2F8392D5

Errors found, file may be invalid!
```