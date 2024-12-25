# SandBlaster: Reversing the Apple Sandbox

## Description

This fork has been updated to support macOS 15.2 kernel sandbox profile data. The original project was authored by Yarden Hamami of Cellebrite Labs.

For a detailed overview of SandBlaster internals, refer to the technical report [SandBlaster: Reversing the Apple Sandbox](https://arxiv.org/abs/1608.04303).

SandBlaster builds upon previous work by [Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox) and Stefan Esser's [code](https://github.com/sektioneins/sandbox_toolkit) and [slides](https://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements).

## Usage

The `extractors` folder contains tools for extracting sandbox profile data and operations. These tools require the path to the Sandbox kext binary and an output path as arguments:

### Extracting Sandbox Data

Use the following commands to extract sandbox operations and profile data:

```sh
python3 extractors/extract_sandbox_operations.py Sandbox.kext/Contents/MacOS/Sandbox .profiles/sandbox_operations
```

```sh
python3 extractors/extract_profile_data_from_kext.py Sandbox.kext/Contents/MacOS/Sandbox .profiles/profile_data
```

### Reversing the Sandbox

After extracting the necessary data, run the following command to reverse the sandbox profile:

```sh
python3 reverse_sandbox.py -o .profiles/sandbox_operations .profiles/profile_data
```

## Credits

- [SandBlaster by Cellebrite Labs](https://github.com/cellebrite-labs/sandblaster), authored by Yarden Hamami.
- [Malus Security SandBlaster Repository](https://github.com/malus-security/sandblaster)
- [XNUSandbox by Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox)
- [Sandbox Toolkit by Stefan Esser](https://github.com/sektioneins/sandbox_toolkit)
