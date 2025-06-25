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

Create a virtual environment and install the required packages:

```sh
pip install -r requirements.txt
```

Run the test suite with `pytest`:

```sh
pytest -q
```

### Reversing the Sandbox
After extracting the necessary data, run the following command to reverse the sandbox profile:

```sh
python -m sandblaster --operations profiles/sandbox_operations profiles/profile_data --output profiles/profile_data_reversed
```

## Credits

- [SandBlaster by Cellebrite Labs by Yarden Hamami](https://github.com/cellebrite-labs/sandblaster)
- [Malus Security SandBlaster Repository](https://github.com/malus-security/sandblaster)
- [XNUSandbox by Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox)
- [Sandbox Toolkit by Stefan Esser](https://github.com/sektioneins/sandbox_toolkit)
