filters = {
    0x01: {
        "name": "",
        "arg_process_fn": get_filter_arg_string_by_offset_with_type
        },
    0x02: {
        "name": "mount-relative",
        "arg_process_fn": get_filter_arg_string_by_offset_with_type
        },
    0x03: {
        "name": "xattr",
        "arg_process_fn": get_filter_arg_string_by_offset
        },
    0x04: {
        "name": "file-mode",
        "arg_process_fn": get_filter_arg_octal_integer
        },
    0x05: {
        "name": "ipc-posix-name",
        "arg_process_fn": get_filter_arg_string_by_offset
        },
    0x06: {
        "name": "global-name",
        "arg_process_fn": get_filter_arg_string_by_offset
        },
    0x07: {
        "name": "local-name",
        "arg_process_fn": get_filter_arg_string_by_offset
        },
    0x08: {
        "name": "local",
        "arg_process_fn": get_filter_arg_network_address
        },
    0x09: {
        "name": "remote",
        "arg_process_fn": get_filter_arg_network_address
        },
    0x0a: {
        "name": "control-name",
        "arg_process_fn": get_filter_arg_string_by_offset
        },
    0x0b: {
        "name": "socket-domain",
        "arg_process_fn": get_filter_arg_socket_domain
        },
    0x0c: {
        "name": "socket-type",
        "arg_process_fn": get_filter_arg_socket_type
        },
    0x0d: {
        "name": "socket-protocol",
        "arg_process_fn": get_filter_arg_integer
        },
    0x0e: {
            "name": "target",
            "arg_process_fn": get_filter_arg_owner
            },
    0x0f: {
            "name": "fsctl-command",
            "arg_process_fn": get_filter_arg_ctl
            },
    0x10: {
            "name": "ioctl-command",
            "arg_process_fn": get_filter_arg_ctl
            },
    0x11: {
            "name": "iokit-user-client-class",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x12: {
            "name": "iokit-property",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x13: {
            "name": "iokit-connection",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x14: {
            "name": "device-major",
            "arg_process_fn": get_filter_arg_integer
            },
    0x15: {
            "name": "device-minor",
            "arg_process_fn": get_filter_arg_integer
            },
    0x16: {
            "name": "device-conforms-to",
            "arg_process_fn": get_filter_arg_string_by_offset_no_skip
            },
    0x17: {
            "name": "extension",
            "arg_process_fn": get_filter_arg_string_by_offset_no_skip
            },
    0x18: {
            "name": "extension-class",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x19: {
            "name": "appleevent-destination",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x1a: {
            "name": "debug-mode",
            "arg_process_fn": get_none
            },
    0x1b: {
            "name": "right-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x1c: {
            "name": "preference-domain",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x1d: {
            "name": "vnode-type",
            "arg_process_fn": get_filter_arg_vnode_type
            },
    0x1e: {
            "name": "require-entitlement",
            "arg_process_fn": get_filter_arg_string_by_offset_no_skip
            },
    0x1f: {
            "name": "entitlement-value",
            "arg_process_fn": get_filter_arg_boolean
            },
    0x20: {
            "name": "entitlement-value",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x21: {
            "name": "kext-bundle-id",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x22: {
            "name": "info-type",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x23: {
            "name": "notification-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x24: {
            "name": "notification-payload",
            "arg_process_fn": get_filter_arg_integer
            },
    0x25: {
            "name": "semaphore-owner",
            "arg_process_fn": get_filter_arg_owner
            },
    0x26: {
            "name": "sysctl-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x27: {
            "name": "process-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x28: {
            "name": "rootless-boot-device-filter",
            "arg_process_fn": get_none
            },
    0x29: {
            "name": "rootless-file-filter",
            "arg_process_fn": get_none
            },
    0x2a: {
            "name": "rootless-disk-filter",
            "arg_process_fn": get_none
            },
    0x2b: {
            "name": "rootless-proc-filter",
            "arg_process_fn": get_none
            },
    0x2c: {
            "name": "privilege-id",
            "arg_process_fn": get_filter_arg_privilege_id
            },
    0x2d: {
            "name": "process-attribute",
            "arg_process_fn": get_filter_arg_process_attribute
            },
    0x2e: {
            "name": "uid",
            "arg_process_fn": get_filter_arg_integer
            },
    0x2f: {
            "name": "nvram-variable",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
    0x30: {
            "name": "csr",
            "arg_process_fn": get_filter_arg_csr
            },
    0x31: {
            "name": "host-special-port",
            "arg_process_fn": get_filter_arg_host_port
            },
    0x81: {
            "name": "regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x82: {
            "name": "mount-relative-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x83: {
            "name": "xattr-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x85: {
            "name": "ipc-posix-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x86: {
            "name": "global-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x87: {
            "name": "local-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x91: {
            "name": "iokit-user-client-class-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x92: {
            "name": "iokit-property-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x93: {
            "name": "iokit-connection-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x98: {
            "name": "extension-class-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x99: {
            "name": "appleevent-destination-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x9b: {
            "name": "right-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0x9c: {
            "name": "preference-domain-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0xa0: {
            "name": "entitlement-value-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0xa1: {
            "name": "kext-bundle-id-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0xa3: {
            "name": "notification-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0xa6: {
            "name": "sysctl-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
    0xa7: {
            "name": "process-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            }
}