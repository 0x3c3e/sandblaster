#!/bin/bash

ipsw download ipsw --macos --version $1 --device $2 --kernel -V
ipsw kernel extract ./*/kernelcache.release* com.apple.security.sandbox

rm -rf profiles
mkdir profiles
SANDBOX_PATH=$(echo */com.apple.security.sandbox)
python extractors/extract_sandbox_operations.py $SANDBOX_PATH profiles/sandbox_operations
python extractors/extract_profile_data_from_kext.py $SANDBOX_PATH profiles/profile_data
