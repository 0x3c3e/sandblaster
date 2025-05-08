#!/bin/bash

rm -rf /tmp/mount /tmp/kdk profiles kernelcaches
mkdir /tmp/mount /tmp/kdk profiles kernelcaches

ipsw download dev --more -o /tmp/kdk
hdiutil attach -noverify -quiet /tmp/kdk/*.dmg -mountpoint /tmp/mount
pkgutil --expand-full /tmp/mount/KernelDebugKit.pkg /tmp/out

cp /tmp/out/KDK.pkg/Payload/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox kernelcaches/com.apple.security.sandbox
umount /tmp/mount
rm -rf /tmp/out

python extractors/extract_sandbox_operations.py kernelcaches/com.apple.security.sandbox profiles/sandbox_operations
python extractors/extract_profile_data_from_kext.py kernelcaches/com.apple.security.sandbox profiles/profile_data
