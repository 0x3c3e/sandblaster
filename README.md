# SandBlaster: Reversing the Apple Sandbox

## Description

This fork has been updated to support macOS 15.2+ kernel sandbox profile data.

## Usage

### Extracting Sandbox Data

```sh
python extractors/extract_sandbox_operations.py Sandbox.kext/Contents/MacOS/Sandbox profiles/sandbox_operations
```

```sh
python extractors/extract_profile_data_from_kext.py Sandbox.kext/Contents/MacOS/Sandbox profiles/profile_data
```

## Testing
Run the test suite with `pytest`:

```sh
pytest -q
```

## Installation

```sh
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Reversing the Sandbox
After extracting the necessary data, run the following command to reverse the sandbox profile:

```sh
sandblaster --operations profiles/sandbox_operations profiles/profile_data --output profiles/profile_data_reversed
```

## Credits

- [Malus Security SandBlaster Repository](https://github.com/malus-security/sandblaster)
- [XNUSandbox by Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox)
- [Sandbox Toolkit by Stefan Esser](https://github.com/sektioneins/sandbox_toolkit)
