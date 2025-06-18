#!/bin/bash

ipsw dyld split /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e -o /tmp/out
cp /tmp/out/usr/lib/libsandbox.1.dylib .
rm -rf /tmp/out