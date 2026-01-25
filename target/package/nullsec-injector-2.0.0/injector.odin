// NullSec Injector - Process Memory Injector & Code Execution Tool
// Language: Odin
// Author: bad-antics
// License: NullSec Proprietary

package injector

import "core:fmt"
import "core:os"
import "core:strings"
import "core:strconv"
import "core:mem"
import "core:c/libc"
import "core:sys/linux"

VERSION :: "1.0.0"

BANNER :: `
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ I N J E C T O R ░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v`

// Configuration
Config :: struct {
    pid: i32,
    shellcode_path: string,
    dll_path: string,
    target_exe: string,
    method: string,
    verbose: bool,
}

// Memory region info
MemRegion :: struct {
    start: uintptr,
    end: uintptr,
    perms: string,
    path: string,
}

// Process info
ProcessInfo :: struct {
    pid: i32,
    name: string,
    cmdline: string,
    uid: i32,
}

// Injection methods enum
InjectionMethod :: enum {
    Classic,
    Ptrace,
    ProcMem,
    Hollow,
}

// =====================================================================
// Utility Functions
// =====================================================================

log_msg :: proc(verbose: bool, msg: string) {
    if verbose {
        fmt.printf("[*] %s\n", msg)
    }
}

log_success :: proc(msg: string) {
    fmt.printf("[+] %s\n", msg)
}

log_error :: proc(msg: string) {
    fmt.printf("[!] %s\n", msg)
}

log_info :: proc(msg: string) {
    fmt.printf("[*] %s\n", msg)
}

// Read file contents
read_file :: proc(path: string) -> ([]byte, bool) {
    data, ok := os.read_entire_file(path)
    return data, ok
}

// Check if running as root
is_root :: proc() -> bool {
    return os.get_uid() == 0
}

// =====================================================================
// Process Operations
// =====================================================================

// Get process info from /proc
get_process_info :: proc(pid: i32) -> (ProcessInfo, bool) {
    info := ProcessInfo{pid = pid}
    
    // Read comm (process name)
    comm_path := fmt.tprintf("/proc/%d/comm", pid)
    if comm_data, ok := os.read_entire_file(comm_path); ok {
        info.name = strings.trim_space(string(comm_data))
        delete(comm_data)
    } else {
        return info, false
    }
    
    // Read cmdline
    cmdline_path := fmt.tprintf("/proc/%d/cmdline", pid)
    if cmdline_data, ok := os.read_entire_file(cmdline_path); ok {
        // Replace null bytes with spaces
        for i in 0..<len(cmdline_data) {
            if cmdline_data[i] == 0 {
                cmdline_data[i] = ' '
            }
        }
        info.cmdline = strings.trim_space(string(cmdline_data))
        delete(cmdline_data)
    }
    
    return info, true
}

// Parse memory maps
parse_maps :: proc(pid: i32) -> []MemRegion {
    regions: [dynamic]MemRegion
    
    maps_path := fmt.tprintf("/proc/%d/maps", pid)
    if data, ok := os.read_entire_file(maps_path); ok {
        lines := strings.split_lines(string(data))
        for line in lines {
            if len(line) == 0 do continue
            
            parts := strings.fields(line)
            if len(parts) >= 2 {
                addr_range := strings.split(parts[0], "-")
                if len(addr_range) == 2 {
                    region := MemRegion{
                        perms = parts[1],
                        path = len(parts) >= 6 ? parts[5] : "",
                    }
                    // Parse addresses (simplified)
                    append(&regions, region)
                }
            }
        }
        delete(data)
    }
    
    return regions[:]
}

// Check if process exists
process_exists :: proc(pid: i32) -> bool {
    path := fmt.tprintf("/proc/%d", pid)
    return os.exists(path)
}

// =====================================================================
// Injection Techniques
// =====================================================================

// Classic ptrace-based injection (Linux)
inject_ptrace :: proc(pid: i32, shellcode: []byte, verbose: bool) -> bool {
    log_msg(verbose, "Using ptrace injection method")
    
    // Check permissions
    if !is_root() {
        log_error("ptrace injection requires root privileges")
        return false
    }
    
    if !process_exists(pid) {
        log_error("Target process does not exist")
        return false
    }
    
    // Display process info
    if info, ok := get_process_info(pid); ok {
        log_info(fmt.tprintf("Target: %s (PID: %d)", info.name, pid))
    }
    
    log_info(fmt.tprintf("Shellcode size: %d bytes", len(shellcode)))
    
    // In real implementation:
    // 1. PTRACE_ATTACH to target process
    // 2. PTRACE_GETREGS to save registers
    // 3. Find executable memory region
    // 4. PTRACE_POKETEXT to write shellcode
    // 5. Modify RIP/EIP to point to shellcode
    // 6. PTRACE_SETREGS with modified registers
    // 7. PTRACE_DETACH
    
    log_msg(verbose, "Attaching to process...")
    log_msg(verbose, "Saving register state...")
    log_msg(verbose, "Finding executable memory region...")
    log_msg(verbose, "Writing shellcode...")
    log_msg(verbose, "Modifying instruction pointer...")
    log_msg(verbose, "Detaching from process...")
    
    // Simulated success
    log_success("Shellcode injected successfully (simulation)")
    log_info("Note: Full implementation requires ptrace syscalls")
    
    return true
}

// /proc/pid/mem injection
inject_proc_mem :: proc(pid: i32, shellcode: []byte, verbose: bool) -> bool {
    log_msg(verbose, "Using /proc/pid/mem injection method")
    
    if !is_root() {
        log_error("/proc/pid/mem injection requires root privileges")
        return false
    }
    
    if !process_exists(pid) {
        log_error("Target process does not exist")
        return false
    }
    
    // Parse memory maps to find writable/executable region
    log_msg(verbose, "Parsing memory maps...")
    regions := parse_maps(pid)
    
    executable_region: ^MemRegion = nil
    for &region in regions {
        // Look for rwx region (rare) or rx region we can modify
        if strings.contains(region.perms, "x") && strings.contains(region.perms, "r") {
            executable_region = &region
            break
        }
    }
    
    if executable_region == nil {
        log_error("No suitable memory region found")
        return false
    }
    
    // In real implementation:
    // 1. Open /proc/pid/mem
    // 2. Seek to target address
    // 3. Write shellcode
    // 4. Trigger execution (signal, thread creation, etc.)
    
    log_msg(verbose, "Found suitable memory region")
    log_msg(verbose, "Opening /proc/pid/mem...")
    log_msg(verbose, "Writing shellcode to memory...")
    log_msg(verbose, "Triggering execution...")
    
    log_success("Injection completed (simulation)")
    
    return true
}

// Process hollowing (spawn + replace)
process_hollow :: proc(target_exe: string, payload: []byte, verbose: bool) -> bool {
    log_msg(verbose, "Using process hollowing technique")
    
    if !os.exists(target_exe) {
        log_error("Target executable not found")
        return false
    }
    
    log_info(fmt.tprintf("Target: %s", target_exe))
    log_info(fmt.tprintf("Payload size: %d bytes", len(payload)))
    
    // Process hollowing steps:
    // 1. Create process in suspended state
    // 2. Unmap original image
    // 3. Allocate memory for payload
    // 4. Write payload to process
    // 5. Set thread context to payload entry
    // 6. Resume process
    
    log_msg(verbose, "Creating suspended process...")
    log_msg(verbose, "Unmapping original image...")
    log_msg(verbose, "Allocating memory for payload...")
    log_msg(verbose, "Writing payload...")
    log_msg(verbose, "Setting entry point...")
    log_msg(verbose, "Resuming process...")
    
    log_success("Process hollowing completed (simulation)")
    
    return true
}

// =====================================================================
// Module Enumeration
// =====================================================================

list_modules :: proc(pid: i32) {
    if !process_exists(pid) {
        log_error("Process does not exist")
        return
    }
    
    info, _ := get_process_info(pid)
    fmt.printf("\n=== Loaded Modules for %s (PID: %d) ===\n\n", info.name, pid)
    
    maps_path := fmt.tprintf("/proc/%d/maps", pid)
    if data, ok := os.read_entire_file(maps_path); ok {
        lines := strings.split_lines(string(data))
        seen := make(map[string]bool)
        
        for line in lines {
            if len(line) == 0 do continue
            
            parts := strings.fields(line)
            if len(parts) >= 6 {
                path := parts[5]
                if strings.has_prefix(path, "/") && !seen[path] {
                    perms := parts[1]
                    addr_range := parts[0]
                    fmt.printf("  %s  %s  %s\n", addr_range, perms, path)
                    seen[path] = true
                }
            }
        }
        delete(data)
    }
    
    fmt.println()
}

// =====================================================================
// Command Handlers
// =====================================================================

handle_inject :: proc(config: Config) {
    if config.pid <= 0 {
        log_error("Invalid PID specified")
        return
    }
    
    if len(config.shellcode_path) == 0 {
        log_error("No shellcode file specified")
        return
    }
    
    shellcode, ok := read_file(config.shellcode_path)
    if !ok {
        log_error("Failed to read shellcode file")
        return
    }
    defer delete(shellcode)
    
    method := config.method if len(config.method) > 0 else "ptrace"
    
    switch method {
    case "ptrace":
        inject_ptrace(config.pid, shellcode, config.verbose)
    case "procmem":
        inject_proc_mem(config.pid, shellcode, config.verbose)
    case:
        log_error(fmt.tprintf("Unknown injection method: %s", method))
    }
}

handle_hollow :: proc(config: Config) {
    if len(config.target_exe) == 0 {
        log_error("No target executable specified")
        return
    }
    
    if len(config.shellcode_path) == 0 {
        log_error("No payload file specified")
        return
    }
    
    payload, ok := read_file(config.shellcode_path)
    if !ok {
        log_error("Failed to read payload file")
        return
    }
    defer delete(payload)
    
    process_hollow(config.target_exe, payload, config.verbose)
}

handle_modules :: proc(config: Config) {
    if config.pid <= 0 {
        log_error("Invalid PID specified")
        return
    }
    
    list_modules(config.pid)
}

// =====================================================================
// CLI
// =====================================================================

print_usage :: proc() {
    fmt.println(`
USAGE:
    injector <command> [options]

COMMANDS:
    inject          Inject shellcode into process
    hollow          Process hollowing
    modules         List loaded modules

OPTIONS:
    -p, --pid          Target process ID
    -s, --shellcode    Shellcode file path
    -t, --target       Target executable (for hollow)
    --method           Injection method (ptrace, procmem)
    -v, --verbose      Verbose output
    -h, --help         Show this help

EXAMPLES:
    injector inject -p 1234 -s shellcode.bin
    injector inject -p 1234 -s shellcode.bin --method procmem
    injector hollow -t /usr/bin/ls -s payload.bin
    injector modules -p 1234

INJECTION METHODS:
    ptrace     - Classic ptrace-based injection (default)
    procmem    - /proc/pid/mem direct memory write

NOTE: Most operations require root privileges.
`)
}

parse_args :: proc() -> (Config, string) {
    config := Config{}
    command := ""
    
    args := os.args[1:]
    i := 0
    
    for i < len(args) {
        arg := args[i]
        
        switch arg {
        case "inject", "hollow", "modules":
            command = arg
        case "-p", "--pid":
            if i + 1 < len(args) {
                i += 1
                config.pid = i32(strconv.atoi(args[i]))
            }
        case "-s", "--shellcode":
            if i + 1 < len(args) {
                i += 1
                config.shellcode_path = args[i]
            }
        case "-t", "--target":
            if i + 1 < len(args) {
                i += 1
                config.target_exe = args[i]
            }
        case "--method":
            if i + 1 < len(args) {
                i += 1
                config.method = args[i]
            }
        case "-v", "--verbose":
            config.verbose = true
        case "-h", "--help":
            command = "help"
        }
        
        i += 1
    }
    
    return config, command
}

main :: proc() {
    fmt.printf("%s%s\n\n", BANNER, VERSION)
    
    config, command := parse_args()
    
    switch command {
    case "inject":
        handle_inject(config)
    case "hollow":
        handle_hollow(config)
    case "modules":
        handle_modules(config)
    case "help":
        print_usage()
    case "":
        print_usage()
    case:
        log_error(fmt.tprintf("Unknown command: %s", command))
        print_usage()
    }
}
