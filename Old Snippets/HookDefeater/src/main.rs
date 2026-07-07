use std::{ffi::CStr, os::raw::c_void, ptr::null_mut};

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS,
    IMAGE_NT_SIGNATURE,
};

fn djb2_hash(input: &[u8]) -> u64 {
    let mut hash: u64 = 0x77347734DEADBEEF;

    for byte in input {
        hash = (hash << 5).wrapping_add(hash).wrapping_add(*byte as u64);
    }

    hash
}

fn get_current_teb() -> PTEB {
    unsafe {
        let mut teb: PTEB = null_mut();
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

fn get_hooked_function_ssn(current_func: *const u8, sys_addr: &mut *mut c_void) -> u16 {
    unsafe {
        let mut prev_stub_cound = 1;

        while prev_stub_cound < 20 {
            let check_addr = current_func.offset(-(prev_stub_cound as isize * 0x20));

            if *check_addr.offset(0) == 0x4C
                && *check_addr.offset(1) == 0x8B
                && *check_addr.offset(2) == 0xD1
                && *check_addr.offset(3) == 0xB8
                && *check_addr.offset(6) == 0x00
                && *check_addr.offset(7) == 0x00
            {
                println!("[+] Found unhooked syscall stub at: {:x?}", check_addr);

                let low = *check_addr.offset(4) as u16;
                let high = *check_addr.offset(5) as u16;
                let ssn = (high << 8) | low;

                let target_ssn = ssn + (prev_stub_cound as u16);

                *sys_addr = current_func.offset(18) as *mut c_void;

                return target_ssn;
            }
            prev_stub_cound += 1;
        }
    }
    return 0;
}

fn get_ssn(hash: u64, sys_addr: &mut *mut c_void) -> u16 {
    unsafe {
        let teb = get_current_teb();

        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            println!("[-] Invalid PEB");
            return 0;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase as *const u8;

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return 0;
        }

        let nt_header = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header");
            return 0;
        }

        let export_dir = (ntdll_base as *const u8)
            .add((*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let address_of_functions =
            (ntdll_base as *const u8).add((*export_dir).AddressOfFunctions as usize) as *const u32;

        let address_of_names =
            (ntdll_base as *const u8).add((*export_dir).AddressOfNames as usize) as *const u32;

        let address_of_name_ordinals = (ntdll_base as *const u8)
            .add((*export_dir).AddressOfNameOrdinals as usize)
            as *const u16;

        for func in 0..(*export_dir).NumberOfFunctions as isize {
            let func_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(func) as usize) as *const i8;

            let oridinal = *address_of_name_ordinals.offset(func) as usize;

            if oridinal >= (*export_dir).NumberOfFunctions as usize {
                continue;
            }

            let function_rva = *address_of_functions.add(oridinal) as usize;
            let function_address = (ntdll_base as *const u8).add(function_rva as usize);

            let c_str = CStr::from_ptr(func_name);

            if let Ok(func_str) = c_str.to_str() {
                if djb2_hash(func_str.to_ascii_lowercase().as_bytes()) == hash {
                    for i in 0..32 {
                        let bytes = function_address as *const u8;
                        let mut ssn: u16 = 0;

                        if *bytes.offset(i) == 0x4C
                            && *bytes.offset(i + 1) == 0x8B
                            && *bytes.offset(i + 2) == 0xD1
                            && *bytes.offset(i + 3) == 0xB8
                            && *bytes.offset(i + 6) == 0x00
                            && *bytes.offset(i + 7) == 0x00
                        {
                            println!("[+] {} is not hooked", func_str);

                            let low = *bytes.offset(i + 4) as u16;
                            let high = *bytes.offset(i + 5) as u16;
                            ssn = (high << 8) | low;

                            *sys_addr = function_address.offset(i + 18) as *mut c_void;
                        } else {
                            print!(
                                "[+] {} is hooked, attempting to find unhooked syscall stub...",
                                func_str
                            );
                            ssn = get_hooked_function_ssn(function_address, sys_addr);
                        }

                        return ssn;
                    }
                }
            }
        }
    }

    return 0;
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        println!("Usage: {} <function_name>", args[0]);
        return;
    }

    println!("[+] Finding hash for function: {}", args[1]);

    let func_name = args[1].to_ascii_lowercase().to_string();

    let hash = djb2_hash(func_name.as_bytes());

    let mut syscall_addr: *mut c_void = null_mut();
    let ssn = get_ssn(hash, &mut syscall_addr);

    println!("[+] SSN: 0x{:X}, Syscall address: {:X?}", ssn, syscall_addr);
}
