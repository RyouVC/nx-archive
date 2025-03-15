# Test fixture assets for nx-archive

This directory contains test fixtures for the `nx-archive` package, data files that are used in the test suite to verify proper operation of the library.

## Test Fixtures

- `Browser.nsp`: A copy of [BrowseNX](https://github.com/crc-32/BrowseNX) version 0.2.0, a homebrew application that launches the internal WebKit browser on the Nintendo Switch.
- `Browser.nsz`: A compressed version of `Browser.nsp`, created by using `nsz` from nicoboss' [NSZ](https://github.com/nicoboss/nsz) script. Used to test NSZ compression and decompression.
- `pfs0-dummy/`: A directory containing files to be used in creation of a dummy PFS0/NSP image.
- `hfs2_mod.py`: A reference implementation of the HFS2 and PFS0 file system as a Python script, ported from Python 2 to Python 3. See https://gist.github.com/yellows8/1a96c2b846f4ebc4bb45d7f7fa1eb7db
    

## Attribution

BrowseNX is developed by crc32 and is licensed under the MIT License. The original source code can be found on the [BrowseNX GitHub repository](https://github.com/crc-32/BrowseNX). The `Browser.nsp` file and its variants are included in this repository for testing purposes only.
