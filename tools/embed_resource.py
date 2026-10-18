#!/usr/bin/env python3
"""Embed FiberRuntime.dll as a custom resource into fiber.exe."""
import sys, ctypes, os

kernel32 = ctypes.windll.kernel32
CUSTOM_TYPE = 101
CUSTOM_NAME = 101

def add_resource(exe_path, data):
    h_update = kernel32.BeginUpdateResourceW(exe_path, False)
    if not h_update:
        err = ctypes.get_last_error()
        print(f"BeginUpdateResource failed: error={err}", file=sys.stderr)
        return False

    # Create a proper ctypes buffer for the data
    buf = ctypes.create_string_buffer(data)
    result = kernel32.UpdateResourceW(
        h_update,
        ctypes.c_void_p(CUSTOM_TYPE),
        ctypes.c_void_p(CUSTOM_NAME),
        0x0400,
        buf,
        len(data)
    )
    last_err = ctypes.get_last_error()

    if not result:
        print(f"UpdateResource failed: error={last_err}", file=sys.stderr)
        kernel32.EndUpdateResourceW(h_update, True)
        return False

    if not kernel32.EndUpdateResourceW(h_update, False):
        err = ctypes.get_last_error()
        print(f"EndUpdateResource failed: error={err}", file=sys.stderr)
        return False

    print(f"Embedded {len(data)} bytes as resource type={CUSTOM_TYPE} name={CUSTOM_NAME}")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <runtime.dll> <launcher.exe>")
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print(f"Runtime DLL not found: {sys.argv[1]}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(sys.argv[2]):
        print(f"Launcher exe not found: {sys.argv[2]}", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        dll_data = f.read()

    if add_resource(sys.argv[2], dll_data):
        print("Done!")
    else:
        sys.exit(1)
