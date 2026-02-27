# nullsec-injector

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
      ░   ░    ░   ░       ░       ░         ░     ░   ░ ░      
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ I N J E C T O R ░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Odin](https://img.shields.io/badge/Odin-1F1F1F?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iI0ZGRiIgZD0iTTEyIDJMMyAyMmgxOEwxMiAyeiIvPjwvc3ZnPg==&logoColor=white)

## Overview

**nullsec-injector** is a process memory injector and code execution tool written in Odin. Combines low-level memory access with a clean, modern syntax for reliable shellcode and DLL injection.

## Features

- 💉 **Shellcode Injection** - Multiple injection techniques
- 📚 **DLL Injection** - Remote DLL loading
- 🧵 **Thread Hijacking** - Existing thread manipulation
- 🔄 **Process Hollowing** - Replace process memory
- 🎭 **APC Injection** - Asynchronous procedure calls
- 📋 **Module Enumeration** - List loaded modules

## Requirements

- Odin compiler (latest)
- Linux or Windows
- Root/Administrator privileges

## Installation

```bash
# Clone repository
git clone https://github.com/bad-antics/nullsec-injector.git
cd nullsec-injector

# Build
odin build injector.odin -out:injector

# Or run directly
odin run injector.odin
```

## Usage

```bash
# Shellcode injection
./injector inject -p 1234 -s shellcode.bin

# DLL injection
./injector dll -p 1234 -d payload.dll

# Thread hijacking
./injector hijack -p 1234 -s shellcode.bin

# Process hollowing
./injector hollow -t target.exe -s payload.exe

# Enumerate modules
./injector modules -p 1234
```

## Options

| Flag | Description |
|------|-------------|
| `-p, --pid` | Target process ID |
| `-s, --shellcode` | Shellcode file path |
| `-d, --dll` | DLL file path |
| `-t, --target` | Target executable |
| `--method` | Injection method |
| `-v, --verbose` | Verbose output |

## Injection Methods

### Shellcode Injection
- Classic VirtualAllocEx + CreateRemoteThread
- NtCreateThreadEx (stealthier)
- Thread context manipulation

### DLL Injection
- LoadLibrary via CreateRemoteThread
- Manual mapping (no LoadLibrary)
- Reflective DLL injection

### Advanced Techniques
- Process hollowing (RunPE)
- APC injection (alertable threads)
- Thread execution hijacking

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized code injection is illegal.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*Part of the NullSec Security Toolkit*


## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)

---

<div align="center">

**Part of the NullSec Security Framework**

</div>
