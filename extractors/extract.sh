#!/bin/bash

rm -rf kernelcaches
mkdir kernelcaches
cp /System/Volumes/Preboot/*/boot/*/System/Library/Caches/com.apple.kernelcaches/kernelcache kernelcaches/
ipsw kernel dec kernelcaches/kernelcache -o kernelcaches/
ipsw kernel extract kernelcaches/kernelcaches/kernelcache.decompressed com.apple.security.sandbox

rm -rf profiles
mkdir profiles
python extractors/extract_sandbox_operations.py kernelcaches/kernelcaches/com.apple.security.sandbox profiles/sandbox_operations
python extractors/extract_profile_data_from_kext.py kernelcaches/kernelcaches/com.apple.security.sandbox profiles/profile_data