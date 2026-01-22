// NullSec Injector - Hardened Process Memory Injection Tool
// Language: Rust (Memory-Safe Systems Programming)
// Author: bad-antics
// License: NullSec Proprietary
// Security Level: Maximum Hardening
//
// Security Features:
// - Memory-safe by design (Rust guarantees)
// - Privilege validation before operations
// - Secure memory handling with zeroization
// - Input validation on all parameters
// - Audit logging capability
// - Defense-in-depth architecture

#![forbid(unsafe_code)]  // Uncomment for safe-only mode
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Constants - Security Critical
// ============================================================================

const VERSION: &str = "2.0.0";
const MAX_SHELLCODE_SIZE: usize = 1024 * 1024; // 1MB limit
const MAX_PID: i32 = 4_194_304; // Linux default max PID
const MIN_PID: i32 = 1;
const MAX_PATH_LEN: usize = 4096;

const BANNER: &str = r#"
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░ I N J E C T O R ░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v"#;

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug)]
pub enum InjectorError {
    InvalidPid(i32),
    PermissionDenied,
    ProcessNotFound(i32),
    ShellcodeTooLarge(usize),
    IoError(io::Error),
    ValidationFailed(String),
    PrivilegeRequired,
    ParseError(String),
}

impl std::fmt::Display for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPid(pid) => write!(f, "Invalid PID: {pid}"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::ProcessNotFound(pid) => write!(f, "Process not found: {pid}"),
            Self::ShellcodeTooLarge(size) => write!(f, "Shellcode too large: {size} bytes"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::ValidationFailed(msg) => write!(f, "Validation failed: {msg}"),
            Self::PrivilegeRequired => write!(f, "Root privileges required"),
            Self::ParseError(msg) => write!(f, "Parse error: {msg}"),
        }
    }
}

impl std::error::Error for InjectorError {}

impl From<io::Error> for InjectorError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

type Result<T> = std::result::Result<T, InjectorError>;

// ============================================================================
// Input Validation (Security Critical)
// ============================================================================

/// Validates a PID is within acceptable range
fn validate_pid(pid: i32) -> Result<i32> {
    if pid < MIN_PID || pid > MAX_PID {
        return Err(InjectorError::InvalidPid(pid));
    }
    Ok(pid)
}

/// Validates a path is safe and exists
fn validate_path(path: &str) -> Result<PathBuf> {
    if path.len() > MAX_PATH_LEN {
        return Err(InjectorError::ValidationFailed("Path too long".into()));
    }
    
    // Check for path traversal attempts
    if path.contains("..") {
        return Err(InjectorError::ValidationFailed("Path traversal detected".into()));
    }
    
    let path = Path::new(path);
    if !path.exists() {
        return Err(InjectorError::ValidationFailed(format!(
            "Path does not exist: {}",
            path.display()
        )));
    }
    
    Ok(path.to_path_buf())
}

/// Validates shellcode size
fn validate_shellcode(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Err(InjectorError::ValidationFailed("Empty shellcode".into()));
    }
    if data.len() > MAX_SHELLCODE_SIZE {
        return Err(InjectorError::ShellcodeTooLarge(data.len()));
    }
    Ok(())
}

// ============================================================================
// Privilege Management
// ============================================================================

/// Check if running as root
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

/// Require root privileges
fn require_root() -> Result<()> {
    if !is_root() {
        return Err(InjectorError::PrivilegeRequired);
    }
    Ok(())
}

// ============================================================================
// Secure Memory Operations
// ============================================================================

/// Securely zero a byte slice
fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// Wrapper for sensitive data with automatic zeroing
pub struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        secure_zero(&mut self.data);
    }
}

// ============================================================================
// Process Information
// ============================================================================

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
    pub cmdline: String,
    pub uid: u32,
    pub state: char,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub path: String,
}

impl MemoryRegion {
    pub fn is_executable(&self) -> bool {
        self.permissions.contains('x')
    }
    
    pub fn is_writable(&self) -> bool {
        self.permissions.contains('w')
    }
    
    pub fn is_readable(&self) -> bool {
        self.permissions.contains('r')
    }
    
    pub fn is_rwx(&self) -> bool {
        self.is_readable() && self.is_writable() && self.is_executable()
    }
    
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

// ============================================================================
// Proc Filesystem Interface
// ============================================================================

/// Check if a process exists
fn process_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Read process name from /proc/[pid]/comm
fn read_process_name(pid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/comm");
    let content = fs::read_to_string(&path)?;
    Ok(content.trim().to_string())
}

/// Read process cmdline from /proc/[pid]/cmdline
fn read_process_cmdline(pid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/cmdline");
    let content = fs::read(&path)?;
    Ok(String::from_utf8_lossy(&content)
        .replace('\0', " ")
        .trim()
        .to_string())
}

/// Read process status
fn read_process_status(pid: i32) -> Result<HashMap<String, String>> {
    let path = format!("/proc/{pid}/status");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    
    let mut status = HashMap::new();
    
    for line in reader.lines() {
        let line = line?;
        if let Some((key, value)) = line.split_once(':') {
            status.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    
    Ok(status)
}

/// Get process info
fn get_process_info(pid: i32) -> Result<ProcessInfo> {
    let pid = validate_pid(pid)?;
    
    if !process_exists(pid) {
        return Err(InjectorError::ProcessNotFound(pid));
    }
    
    let name = read_process_name(pid)?;
    let cmdline = read_process_cmdline(pid)?;
    let status = read_process_status(pid)?;
    
    let uid = status
        .get("Uid")
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    let state = status
        .get("State")
        .and_then(|s| s.chars().next())
        .unwrap_or('?');
    
    Ok(ProcessInfo {
        pid,
        name,
        cmdline,
        uid,
        state,
    })
}

/// Parse /proc/[pid]/maps
fn read_memory_maps(pid: i32) -> Result<Vec<MemoryRegion>> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    
    let mut regions = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }
    
    Ok(regions)
}

/// Parse a single line from /proc/[pid]/maps
fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    
    let (start_str, end_str) = parts[0].split_once('-')?;
    let start = u64::from_str_radix(start_str, 16).ok()?;
    let end = u64::from_str_radix(end_str, 16).ok()?;
    
    let permissions = parts[1].to_string();
    let offset = u64::from_str_radix(parts[2], 16).ok()?;
    let device = parts[3].to_string();
    let inode = parts[4].parse().ok()?;
    let path = parts.get(5).map_or(String::new(), |s| s.to_string());
    
    Some(MemoryRegion {
        start,
        end,
        permissions,
        offset,
        device,
        inode,
        path,
    })
}

// ============================================================================
// Injection Methods (Analysis Only - Requires unsafe for actual injection)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub enum InjectionMethod {
    PtraceWrite,
    ProcMem,
    ProcessHollow,
    SharedLibrary,
}

impl std::fmt::Display for InjectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PtraceWrite => write!(f, "ptrace-write"),
            Self::ProcMem => write!(f, "proc-mem"),
            Self::ProcessHollow => write!(f, "process-hollow"),
            Self::SharedLibrary => write!(f, "shared-library"),
        }
    }
}

/// Find suitable injection points in a process
fn find_injection_points(pid: i32) -> Result<Vec<MemoryRegion>> {
    let regions = read_memory_maps(pid)?;
    
    // Look for executable regions or regions we can make executable
    let suitable: Vec<MemoryRegion> = regions
        .into_iter()
        .filter(|r| {
            (r.is_executable() && r.is_writable()) || // RWX (dangerous but easy)
            (r.is_writable() && r.path.is_empty())    // Anonymous writable
        })
        .collect();
    
    Ok(suitable)
}

/// Find code caves (sequences of NOPs or zeros)
fn find_code_caves(pid: i32, min_size: usize) -> Result<Vec<(u64, usize)>> {
    let regions = read_memory_maps(pid)?;
    let mut caves = Vec::new();
    
    for region in regions.iter().filter(|r| r.is_executable()) {
        // Would read memory via /proc/[pid]/mem
        // For now, just report executable regions
        if region.size() as usize >= min_size {
            caves.push((region.start, region.size() as usize));
        }
    }
    
    Ok(caves)
}

// ============================================================================
// Security Analysis
// ============================================================================

/// Analyze process security posture
fn analyze_process_security(pid: i32) -> Result<()> {
    println!("\n[*] Security Analysis for PID: {pid}");
    println!("─────────────────────────────────────────");
    
    let info = get_process_info(pid)?;
    println!("  Name:     {}", info.name);
    println!("  Command:  {}", info.cmdline);
    println!("  UID:      {}", info.uid);
    println!("  State:    {}", info.state);
    
    let regions = read_memory_maps(pid)?;
    
    // Count dangerous regions
    let rwx_count = regions.iter().filter(|r| r.is_rwx()).count();
    let exec_count = regions.iter().filter(|r| r.is_executable()).count();
    let write_count = regions.iter().filter(|r| r.is_writable()).count();
    
    println!("\n[*] Memory Layout:");
    println!("  Total regions:    {}", regions.len());
    println!("  Executable:       {exec_count}");
    println!("  Writable:         {write_count}");
    
    if rwx_count > 0 {
        println!("  \x1b[31mRWX (DANGEROUS): {rwx_count}\x1b[0m");
    } else {
        println!("  RWX:              0 ✓");
    }
    
    // Show RWX regions if any
    if rwx_count > 0 {
        println!("\n[!] RWX Regions:");
        for region in regions.iter().filter(|r| r.is_rwx()) {
            println!(
                "    0x{:012x}-0x{:012x} {}",
                region.start, region.end, region.path
            );
        }
    }
    
    Ok(())
}

// ============================================================================
// Audit Logging
// ============================================================================

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn log_action(action: &str, details: &str) {
    let ts = get_timestamp();
    eprintln!("[AUDIT] ts={ts} action=\"{action}\" details=\"{details}\"");
}

// ============================================================================
// Command Line Interface
// ============================================================================

#[derive(Debug)]
struct Config {
    pid: Option<i32>,
    shellcode_path: Option<String>,
    method: InjectionMethod,
    analyze_only: bool,
    list_processes: bool,
    verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pid: None,
            shellcode_path: None,
            method: InjectionMethod::PtraceWrite,
            analyze_only: false,
            list_processes: false,
            verbose: false,
        }
    }
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config::default();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--pid" => {
                if i + 1 < args.len() {
                    config.pid = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "-s" | "--shellcode" => {
                if i + 1 < args.len() {
                    config.shellcode_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-m" | "--method" => {
                if i + 1 < args.len() {
                    config.method = match args[i + 1].as_str() {
                        "ptrace" => InjectionMethod::PtraceWrite,
                        "procmem" => InjectionMethod::ProcMem,
                        "hollow" => InjectionMethod::ProcessHollow,
                        "library" => InjectionMethod::SharedLibrary,
                        _ => InjectionMethod::PtraceWrite,
                    };
                    i += 1;
                }
            }
            "-a" | "--analyze" => config.analyze_only = true,
            "-l" | "--list" => config.list_processes = true,
            "-v" | "--verbose" => config.verbose = true,
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    
    config
}

fn print_usage() {
    println!(
        r#"USAGE:
    injector [options]

OPTIONS:
    -p, --pid <pid>         Target process ID
    -s, --shellcode <file>  Path to shellcode file
    -m, --method <method>   Injection method (ptrace, procmem, hollow, library)
    -a, --analyze           Analyze process only, don't inject
    -l, --list              List running processes
    -v, --verbose           Verbose output
    -h, --help              Show this help

EXAMPLES:
    injector -l                           # List processes
    injector -p 1234 -a                   # Analyze PID 1234
    injector -p 1234 -s payload.bin       # Inject payload
    injector -p 1234 -s sc.bin -m procmem # Use /proc/[pid]/mem method
"#
    );
}

fn list_processes() -> Result<()> {
    println!("\n[*] Running Processes");
    println!("─────────────────────────────────────────────────────");
    println!("{:>7}  {:>7}  {:<20}  {}", "PID", "UID", "NAME", "COMMAND");
    println!("─────────────────────────────────────────────────────");
    
    let entries = fs::read_dir("/proc")?;
    
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(pid_str) = name.to_str() {
            if let Ok(pid) = pid_str.parse::<i32>() {
                if let Ok(info) = get_process_info(pid) {
                    let cmd = if info.cmdline.len() > 40 {
                        format!("{}...", &info.cmdline[..40])
                    } else {
                        info.cmdline
                    };
                    println!(
                        "{:>7}  {:>7}  {:<20}  {}",
                        pid, info.uid, info.name, cmd
                    );
                }
            }
        }
    }
    
    Ok(())
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    println!("{}{}\n", BANNER, VERSION);
    
    let config = parse_args();
    
    if config.list_processes {
        if let Err(e) = list_processes() {
            eprintln!("[!] Error: {e}");
            process::exit(1);
        }
        return;
    }
    
    let Some(pid) = config.pid else {
        eprintln!("[!] No PID specified. Use -p <pid> or -l to list processes.");
        process::exit(1);
    };
    
    if let Err(e) = validate_pid(pid) {
        eprintln!("[!] {e}");
        process::exit(1);
    }
    
    if config.analyze_only {
        if let Err(e) = analyze_process_security(pid) {
            eprintln!("[!] Error: {e}");
            process::exit(1);
        }
        return;
    }
    
    // For actual injection, would need unsafe code and root
    if let Err(e) = require_root() {
        eprintln!("[!] {e}");
        eprintln!("[*] Run with sudo for injection capabilities");
        process::exit(1);
    }
    
    log_action("inject_attempt", &format!("pid={pid} method={}", config.method));
    
    let Some(sc_path) = config.shellcode_path else {
        eprintln!("[!] No shellcode specified. Use -s <file>");
        process::exit(1);
    };
    
    println!("[*] Target PID: {pid}");
    println!("[*] Method: {}", config.method);
    println!("[*] Shellcode: {sc_path}");
    
    // Read and validate shellcode
    let shellcode = match fs::read(&sc_path) {
        Ok(data) => SecureBytes::new(data),
        Err(e) => {
            eprintln!("[!] Failed to read shellcode: {e}");
            process::exit(1);
        }
    };
    
    if let Err(e) = validate_shellcode(shellcode.as_slice()) {
        eprintln!("[!] {e}");
        process::exit(1);
    }
    
    println!("[*] Shellcode size: {} bytes", shellcode.len());
    
    // Find injection points
    match find_injection_points(pid) {
        Ok(points) => {
            if points.is_empty() {
                println!("[!] No suitable injection points found");
            } else {
                println!("[+] Found {} potential injection points:", points.len());
                for (i, point) in points.iter().take(5).enumerate() {
                    println!(
                        "    [{i}] 0x{:012x} ({} bytes) {}",
                        point.start,
                        point.size(),
                        point.permissions
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("[!] Error finding injection points: {e}");
        }
    }
    
    println!("\n[*] Injection analysis complete");
    println!("[*] Actual injection requires additional unsafe code");
}
