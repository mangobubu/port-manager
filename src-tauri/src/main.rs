#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use serde::Serialize;
use std::collections::HashMap;
use std::process::Command;

#[cfg(target_os = "windows")]
use std::{
    ffi::{OsStr, OsString},
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr::{null, null_mut},
};

#[cfg(target_os = "macos")]
use std::ffi::CStr;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
            TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        },
    },
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PortEntry {
    id: String,
    protocol: String,
    local_address: String,
    local_port: u16,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    state: Option<String>,
    pid: u32,
    process_name: String,
    process_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStatus {
    elevated: bool,
    platform: String,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    name: String,
    path: Option<String>,
}

#[derive(Debug, Clone)]
struct RawPortEntry {
    protocol: String,
    local_address: String,
    local_port: u16,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    state: Option<String>,
    pid: u32,
    process_name_hint: Option<String>,
    id_hint: String,
}

#[tauri::command]
fn get_app_status() -> AppStatus {
    AppStatus {
        elevated: is_elevated(),
        platform: std::env::consts::OS.to_string(),
    }
}

#[tauri::command]
fn list_ports() -> Result<Vec<PortEntry>, String> {
    let raw_entries = list_ports_platform()?;
    let process_names = process_names_by_pid();
    let mut process_cache: HashMap<u32, ProcessInfo> = HashMap::new();
    let mut rows = Vec::with_capacity(raw_entries.len());

    for (index, raw) in raw_entries.into_iter().enumerate() {
        let process = process_cache.entry(raw.pid).or_insert_with(|| {
            build_process_info(raw.pid, raw.process_name_hint.as_deref(), &process_names)
        });

        rows.push(PortEntry {
            id: format!(
                "{}-{}-{}-{}-{}-{}",
                raw.protocol, raw.local_address, raw.local_port, raw.pid, raw.id_hint, index
            ),
            protocol: raw.protocol,
            local_address: raw.local_address,
            local_port: raw.local_port,
            remote_address: raw.remote_address,
            remote_port: raw.remote_port,
            state: raw.state,
            pid: raw.pid,
            process_name: process.name.clone(),
            process_path: process.path.clone(),
        });
    }

    rows.sort_by(|a, b| {
        a.local_port
            .cmp(&b.local_port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    Ok(rows)
}

#[tauri::command]
fn kill_process(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("PID 0 cannot be terminated".to_string());
    }

    if pid == std::process::id() {
        return Err("The port manager process itself cannot be terminated".to_string());
    }

    terminate_process(pid)
}

fn build_process_info(
    pid: u32,
    name_hint: Option<&str>,
    process_names: &HashMap<u32, String>,
) -> ProcessInfo {
    let path = process_path(pid);
    let name = process_names
        .get(&pid)
        .cloned()
        .or_else(|| {
            name_hint
                .map(str::to_string)
                .filter(|name| !name.is_empty())
        })
        .or_else(|| {
            path.as_ref().and_then(|path| {
                std::path::Path::new(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
        })
        .unwrap_or_else(|| format!("PID {pid}"));

    ProcessInfo { name, path }
}

fn parse_endpoint(value: &str) -> (String, Option<u16>) {
    if value == "*" || value == "*:*" {
        return ("*".to_string(), None);
    }

    if let Some(rest) = value.strip_prefix('[') {
        if let Some((address, port)) = rest.split_once("]:") {
            return (address.to_string(), parse_port(port));
        }
    }

    if let Some((address, port)) = value.rsplit_once(':') {
        return (address.to_string(), parse_port(port));
    }

    (value.to_string(), None)
}

fn parse_port(value: &str) -> Option<u16> {
    if value == "*" {
        return None;
    }
    value.parse::<u16>().ok()
}

#[cfg(target_os = "windows")]
fn list_ports_platform() -> Result<Vec<RawPortEntry>, String> {
    list_ports_windows()
}

#[cfg(target_os = "macos")]
fn list_ports_platform() -> Result<Vec<RawPortEntry>, String> {
    list_ports_macos()
}

#[cfg(target_os = "linux")]
fn list_ports_platform() -> Result<Vec<RawPortEntry>, String> {
    list_ports_linux()
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn list_ports_platform() -> Result<Vec<RawPortEntry>, String> {
    Err("Unsupported platform".to_string())
}

#[cfg(target_os = "windows")]
fn list_ports_windows() -> Result<Vec<RawPortEntry>, String> {
    let output = Command::new("netstat")
        .args(["-a", "-n", "-o"])
        .output()
        .map_err(|err| format!("Failed to run netstat: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "netstat failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let protocol = parts[0].to_ascii_uppercase();
        if protocol != "TCP" && protocol != "UDP" {
            continue;
        }

        let (local_address, local_port, remote_address, remote_port, state, pid) =
            match protocol.as_str() {
                "TCP" if parts.len() >= 5 => {
                    let (local_address, local_port) = parse_endpoint(parts[1]);
                    let (remote_address, remote_port) = parse_endpoint(parts[2]);
                    let state = Some(parts[3].to_string());
                    let pid = parts[4].parse::<u32>().ok();
                    (
                        local_address,
                        local_port,
                        remote_address,
                        remote_port,
                        state,
                        pid,
                    )
                }
                "UDP" if parts.len() >= 4 => {
                    let (local_address, local_port) = parse_endpoint(parts[1]);
                    let (remote_address, remote_port) = parse_endpoint(parts[2]);
                    let pid = parts[3].parse::<u32>().ok();
                    (
                        local_address,
                        local_port,
                        remote_address,
                        remote_port,
                        None,
                        pid,
                    )
                }
                _ => continue,
            };

        let Some(local_port) = local_port else {
            continue;
        };
        let Some(pid) = pid else {
            continue;
        };

        rows.push(RawPortEntry {
            protocol,
            local_address,
            local_port,
            remote_address: Some(remote_address),
            remote_port,
            state,
            pid,
            process_name_hint: None,
            id_hint: index.to_string(),
        });
    }

    Ok(rows)
}

#[cfg(target_os = "macos")]
fn list_ports_macos() -> Result<Vec<RawPortEntry>, String> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", "-iUDP"])
        .output()
        .map_err(|err| format!("Failed to run lsof: {err}"))?;

    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!(
            "lsof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();

    for (index, line) in text.lines().enumerate() {
        if index == 0 && line.contains("COMMAND") && line.contains("PID") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let pid = match parts[1].parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let protocol = parts[7].to_ascii_uppercase();
        if protocol != "TCP" && protocol != "UDP" {
            continue;
        }

        let endpoint = parts[8];
        let (local_raw, remote_raw) = endpoint
            .split_once("->")
            .map(|(local, remote)| (local, Some(remote)))
            .unwrap_or((endpoint, None));

        let (local_address, local_port) = parse_endpoint(local_raw);
        let Some(local_port) = local_port else {
            continue;
        };

        let (remote_address, remote_port) = remote_raw
            .map(parse_endpoint)
            .unwrap_or_else(|| ("*".to_string(), None));

        let state = parts
            .get(9)
            .map(|state| state.trim_matches(['(', ')']).to_ascii_uppercase())
            .map(|state| {
                if state == "LISTEN" {
                    "LISTENING".to_string()
                } else {
                    state
                }
            });

        rows.push(RawPortEntry {
            protocol,
            local_address,
            local_port,
            remote_address: Some(remote_address),
            remote_port,
            state,
            pid,
            process_name_hint: Some(parts[0].to_string()),
            id_hint: index.to_string(),
        });
    }

    Ok(rows)
}

#[cfg(target_os = "linux")]
fn list_ports_linux() -> Result<Vec<RawPortEntry>, String> {
    let inode_to_pid = linux_socket_inode_to_pid();
    let mut rows = Vec::new();

    linux_read_proc_net("/proc/net/tcp", "TCP", false, &inode_to_pid, &mut rows)?;
    linux_read_proc_net("/proc/net/tcp6", "TCP", true, &inode_to_pid, &mut rows)?;
    linux_read_proc_net("/proc/net/udp", "UDP", false, &inode_to_pid, &mut rows)?;
    linux_read_proc_net("/proc/net/udp6", "UDP", true, &inode_to_pid, &mut rows)?;

    Ok(rows)
}

#[cfg(target_os = "linux")]
fn linux_read_proc_net(
    path: &str,
    protocol: &str,
    ipv6: bool,
    inode_to_pid: &HashMap<String, u32>,
    rows: &mut Vec<RawPortEntry>,
) -> Result<(), String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(());
    };

    for (index, line) in text.lines().enumerate().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let Some((local_address, local_port)) = linux_parse_proc_endpoint(parts[1], ipv6) else {
            continue;
        };
        let Some((remote_address, remote_port)) = linux_parse_proc_endpoint(parts[2], ipv6) else {
            continue;
        };

        let inode = parts[9].to_string();
        let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);
        let state = if protocol == "TCP" {
            Some(linux_tcp_state(parts[3]).to_string())
        } else {
            None
        };

        rows.push(RawPortEntry {
            protocol: protocol.to_string(),
            local_address,
            local_port,
            remote_address: Some(remote_address),
            remote_port: Some(remote_port),
            state,
            pid,
            process_name_hint: None,
            id_hint: format!("{path}-{inode}-{index}"),
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_parse_proc_endpoint(value: &str, ipv6: bool) -> Option<(String, u16)> {
    let (address_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ipv6 {
        if address_hex.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 16];
        for block in 0..4 {
            let start = block * 8;
            let value = u32::from_str_radix(&address_hex[start..start + 8], 16).ok()?;
            bytes[block * 4..block * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        Some((std::net::Ipv6Addr::from(bytes).to_string(), port))
    } else {
        let value = u32::from_str_radix(address_hex, 16).ok()?;
        let bytes = value.to_le_bytes();
        Some((
            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
            port,
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_tcp_state(value: &str) -> &'static str {
    match value {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECEIVED",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTENING",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

#[cfg(target_os = "linux")]
fn linux_socket_inode_to_pid() -> HashMap<String, u32> {
    let mut result = HashMap::new();
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return result;
    };

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        let fd_path = entry.path().join("fd");
        let Ok(fd_entries) = std::fs::read_dir(fd_path) else {
            continue;
        };

        for fd in fd_entries.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|v| v.strip_suffix(']'))
            {
                result.entry(inode.to_string()).or_insert(pid);
            }
        }
    }

    result
}

#[cfg(target_os = "windows")]
fn process_names_by_pid() -> HashMap<u32, String> {
    let mut result = HashMap::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }

        let mut entry = std::mem::zeroed::<PROCESSENTRY32W>();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = wide_to_string(&entry.szExeFile);
                result.insert(entry.th32ProcessID, name);

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    result
}

#[cfg(target_os = "linux")]
fn process_names_by_pid() -> HashMap<u32, String> {
    let mut result = HashMap::new();
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return result;
    };

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };
        if let Ok(name) = std::fs::read_to_string(entry.path().join("comm")) {
            result.insert(pid, name.trim().to_string());
        }
    }

    result
}

#[cfg(target_os = "macos")]
fn process_names_by_pid() -> HashMap<u32, String> {
    HashMap::new()
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn process_names_by_pid() -> HashMap<u32, String> {
    HashMap::new()
}

#[cfg(target_os = "windows")]
fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if ok == 0 || size == 0 {
            None
        } else {
            Some(
                OsString::from_wide(&buffer[..size as usize])
                    .to_string_lossy()
                    .to_string(),
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn process_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().to_string())
}

#[cfg(target_os = "macos")]
fn process_path(pid: u32) -> Option<String> {
    let mut buffer = vec![0i8; 4096];
    let length = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len() as u32,
        )
    };

    if length <= 0 {
        None
    } else {
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .ok()
            .map(str::to_string)
    }
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn process_path(_pid: u32) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn terminate_process(pid: u32) -> Result<(), String> {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return Err(format!(
                "Failed to open PID {pid}. Run as administrator. Windows error: {}",
                GetLastError()
            ));
        }

        let ok = TerminateProcess(handle, 1);
        CloseHandle(handle);

        if ok == 0 {
            Err(format!(
                "Failed to terminate PID {pid}. Windows error: {}",
                GetLastError()
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_process(pid: u32) -> Result<(), String> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "Failed to terminate PID {pid}. Run as administrator/root. OS error: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn terminate_process(_pid: u32) -> Result<(), String> {
    Err("Unsupported platform".to_string())
}

fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        is_elevated_windows()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = std::mem::zeroed::<TOKEN_ELEVATION>();
        let mut returned_size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_size,
        );
        CloseHandle(token);

        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(target_os = "windows")]
fn ensure_elevated_or_relaunch() {
    if is_elevated_windows() {
        return;
    }

    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let args = quote_windows_args(std::env::args_os().skip(1));
    let operation = to_wide("runas");
    let exe_wide = os_to_wide(exe.as_os_str());
    let args_wide = to_wide(&args);

    unsafe {
        let result = ShellExecuteW(
            null_mut(),
            operation.as_ptr(),
            exe_wide.as_ptr(),
            if args.is_empty() {
                null()
            } else {
                args_wide.as_ptr()
            },
            null(),
            SW_SHOWNORMAL,
        );

        if (result as isize) > 32 {
            std::process::exit(0);
        }
    }
}

#[cfg(target_os = "macos")]
fn ensure_elevated_or_relaunch() {
    if is_elevated() || std::env::var_os("PORT_MANAGER_ELEVATED_CHILD").is_some() {
        return;
    }

    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let mut command = format!(
        "PORT_MANAGER_ELEVATED_CHILD=1 {}",
        shell_quote(&exe.to_string_lossy())
    );
    for arg in std::env::args_os().skip(1) {
        command.push(' ');
        command.push_str(&shell_quote(&arg.to_string_lossy()));
    }
    command.push_str(" >/dev/null 2>&1 &");

    let script = format!(
        "do shell script {} with administrator privileges",
        apple_script_quote(&command)
    );

    if Command::new("osascript")
        .args(["-e", &script])
        .spawn()
        .is_ok()
    {
        std::process::exit(0);
    }
}

#[cfg(target_os = "linux")]
fn ensure_elevated_or_relaunch() {
    if is_elevated() || std::env::var_os("PORT_MANAGER_ELEVATED_CHILD").is_some() {
        return;
    }

    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let mut command = Command::new("pkexec");
    command.arg("env");
    command.arg("PORT_MANAGER_ELEVATED_CHILD=1");
    for key in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Ok(value) = std::env::var(key) {
            command.arg(format!("{key}={value}"));
        }
    }
    command.arg(exe);
    command.args(std::env::args_os().skip(1));

    if command.spawn().is_ok() {
        std::process::exit(0);
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn ensure_elevated_or_relaunch() {}

#[cfg(target_os = "windows")]
fn quote_windows_args<I>(args: I) -> String
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    args.into_iter()
        .map(|arg| quote_windows_arg(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "windows")]
fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }

    if !arg.chars().any(|ch| ch.is_whitespace() || ch == '"') {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;

    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }

    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(target_os = "macos")]
fn apple_script_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "windows")]
fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
fn os_to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn wide_to_string(value: &[u16]) -> String {
    let len = value.iter().position(|ch| *ch == 0).unwrap_or(value.len());
    OsString::from_wide(&value[..len])
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_endpoint() {
        let (address, port) = parse_endpoint("127.0.0.1:8080");
        assert_eq!(address, "127.0.0.1");
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn parses_ipv6_endpoint() {
        let (address, port) = parse_endpoint("[::1]:443");
        assert_eq!(address, "::1");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parses_wildcard_endpoint() {
        let (address, port) = parse_endpoint("*:*");
        assert_eq!(address, "*");
        assert_eq!(port, None);
    }

    #[test]
    fn refuses_to_terminate_self_or_pid_zero() {
        assert!(kill_process(0).is_err());
        assert!(kill_process(std::process::id()).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_process_info_smoke_test() {
        let pid = std::process::id();
        let names = process_names_by_pid();
        assert!(names.contains_key(&pid));
        assert!(process_path(pid).is_some());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_port_listing_smoke_test() {
        let rows = list_ports_windows().expect("windows port listing should succeed");
        assert!(rows
            .iter()
            .all(|row| row.protocol == "TCP" || row.protocol == "UDP"));
    }
}

fn main() {
    ensure_elevated_or_relaunch();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_app_status,
            list_ports,
            kill_process
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Tauri app");
}
