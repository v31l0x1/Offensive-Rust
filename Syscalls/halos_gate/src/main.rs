use std::{
    ffi::CStr,
    io::Bytes,
    ops::{Add, Sub},
    ptr::null_mut,
};

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use windows_sys::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64,
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

fn get_current_teb() -> PTEB {
    let mut teb: PTEB = null_mut();
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
        );
        #[cfg(target_arch = "x86")]
        std::arch::asm!(
            "mov {}, fs:[0x18]",
            out(reg) teb,
        );
        teb
    }
}

fn get_hooked_ssn(func_addr: *const u8) -> u32 {
    let mut ssn: u32 = 0;
    let mut stub_count = 1;
    let mut org_func_addr = func_addr;

    unsafe {
        org_func_addr = org_func_addr.sub(0x20);
        let bytes = org_func_addr as *const u8;

        loop {
            if *bytes.offset(0) == 0x4C
                && *bytes.offset(1) == 0x8B
                && *bytes.offset(2) == 0xD1
                && *bytes.offset(3) == 0xB8
                && *bytes.offset(6) == 0x00
                && *bytes.offset(7) == 0x00
            {
                let low = *bytes.offset(4) as u32;
                let high = *bytes.offset(5) as u32;
                ssn = (high << 8) | low;
                ssn = ssn.add(stub_count);

                println!("[+] SNN: 0x{:0X}", ssn);
                println!("[+] Found unhooked stub at {:p}", org_func_addr);
                return ssn;
            } else {
                stub_count += 1;
                org_func_addr = org_func_addr.sub(0x20);
            }

            if stub_count >= 10 {
                break;
            }
        }

        stub_count = 1;
        org_func_addr = func_addr;
        org_func_addr = org_func_addr.add(0x20);

        loop {
            if *bytes.offset(0) == 0x4C
                && *bytes.offset(1) == 0x8B
                && *bytes.offset(2) == 0xD1
                && *bytes.offset(3) == 0xB8
                && *bytes.offset(6) == 0x00
                && *bytes.offset(7) == 0x00
            {
                let low = *bytes.offset(4) as u32;
                let high = *bytes.offset(5) as u32;
                ssn = (high << 8) | low;
                ssn = ssn.sub(stub_count);

                println!("[+] SNN: 0x{:0X}", ssn);
                println!("[+] Found unhooked stub at {:p}", org_func_addr);
                return ssn;
            } else {
                stub_count += 1;
                org_func_addr = org_func_addr.add(0x20);
            }

            if stub_count >= 10 {
                break;
            }
        }
    }

    ssn
}

fn get_ssn(func_name: &str) -> u32 {
    let mut ssn: u32 = 0;

    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion < 10 {
            println!("[-] Invalid PEB");
            return ssn;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase as *const u8;
        println!("[+] ntdll.dll base address: {:p}", ntdll_base);

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return ssn;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header");
            return ssn;
        }

        let export_directory = (ntdll_base as *const u8)
            .add((*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let address_of_functions = (ntdll_base as *const u8)
            .add((*export_directory).AddressOfFunctions as usize)
            as *const u32;
        let address_of_names = (ntdll_base as *const u8)
            .add((*export_directory).AddressOfNames as usize)
            as *const u32;
        let address_of_name_ordinals = (ntdll_base as *const u8)
            .add((*export_directory).AddressOfNameOrdinals as usize)
            as *const u16;

        for i in 0..(*export_directory).NumberOfFunctions as isize {
            let f_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(i) as usize) as *const i8;

            let ordinal = *address_of_name_ordinals.offset(i) as usize;

            if ordinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            let funtion_rva = *address_of_functions.offset(ordinal as isize);
            let func_addr = (ntdll_base as *const u8).add(funtion_rva as usize);

            let c_str = CStr::from_ptr(f_name);

            if let Ok(funcname) = c_str.to_str() {
                if func_name.eq_ignore_ascii_case(funcname) {
                    println!(
                        "[+] Found function: {} at address: {:p}",
                        funcname, func_addr
                    );

                    let bytes = func_addr as *const u8;

                    for i in 0..32 {
                        if *bytes.offset(i) == 0x4c
                            && *bytes.offset(i + 1) == 0x8b
                            && *bytes.offset(i + 2) == 0xd1
                            && *bytes.offset(i + 3) == 0xb8
                            && *bytes.offset(i + 6) == 0x00
                            && *bytes.offset(i + 7) == 0x00
                        {
                            let low = *bytes.offset(i + 4) as u32;
                            let high = *bytes.offset(i + 5) as u32;
                            let ssn = (high << 8) | low;

                            return ssn;
                        } else {
                            println!("[+] Hook detected!..");

                            ssn = get_hooked_ssn(func_addr);

                            return ssn;
                        }
                    }
                }
            }
        }
    }

    ssn
}

fn main() {
    let ssn = get_ssn("NtAllocateVirtualMemory");
    println!("[+] SSN for NtAllocateVirtualMemory: 0x{:0X}", ssn);
}
