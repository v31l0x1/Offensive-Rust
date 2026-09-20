#![allow(non_snake_case)]
use std::{os::raw::c_void, ptr::null_mut};

use ntapi::{
    ntexapi::NtCreateEvent,
    ntobapi::{NtSignalAndWaitForSingleObject, NtWaitForSingleObject},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, NTSTATUS},
    System::{
        Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64},
        Kernel::NotificationEvent,
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Memory::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{
            EVENT_ALL_ACCESS, GetCurrentProcess, INFINITE, WT_EXECUTEINWAITTHREAD,
            WT_EXECUTEONLYONCE,
        },
    },
};

unsafe extern "system" {
    fn RtlRegisterWait(
        WaitHandle: *mut *mut c_void,
        Handle: *mut c_void,
        Function: *const c_void,
        Context: *const c_void,
        Milliseconds: u32,
        Flags: u32,
    ) -> NTSTATUS;
}

#[repr(C)]
struct USTRING {
    len: u32,
    max_len: u32,
    buffer: *mut u8,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct AlignedContext(CONTEXT);

fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

#[cfg(any(target_arch = "x86_64"))]
fn gen_random() -> u32 {
    unsafe {
        use std::arch::x86_64::_rdrand32_step;

        let mut seed: u32 = 0;
        _rdrand32_step(&mut seed);
        seed
    }
}

fn ziliean(time: u32) {
    unsafe {
        let mut ctx_init = AlignedContext(CONTEXT::default());
        let mut key: [u8; 16] = [0; 16];
        let mut timer: *mut c_void = null_mut();
        let mut delay: u32 = 0;
        let mut event_start: *mut c_void = null_mut();
        let mut event_timer: *mut c_void = null_mut();
        let mut event_end: *mut c_void = null_mut();
        let mut event_wait: *mut c_void = null_mut();
        let mut old_protection: u32 = 0;

        let image_base: *mut c_void = GetModuleHandleA(null_mut());
        let dos_header = image_base as *const IMAGE_DOS_HEADER;
        let nt_header =
            image_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let image_size = (*nt_header).OptionalHeader.SizeOfImage;

        println!("[*] Image Base: {:p}", image_base);

        let kernel32 = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const u8);
        let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);
        let mut advapi32 = GetModuleHandleA("advapi32.dll\0".as_ptr() as *const u8);

        if advapi32.is_null() {
            advapi32 = LoadLibraryA("advapi32.dll\0".as_ptr() as *const u8);
        }

        if kernel32.is_null() || ntdll.is_null() || advapi32.is_null() {
            println!("[-] Failed to load DLLs");
            return;
        }

        let wait_for_single_object_ex =
            GetProcAddress(kernel32, "WaitForSingleObjectEx\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        let virtual_protect = GetProcAddress(kernel32, "VirtualProtect\0".as_ptr() as *const u8)
            .unwrap() as *mut c_void;
        let set_event =
            GetProcAddress(kernel32, "SetEvent\0".as_ptr() as *const u8).unwrap() as *mut c_void;
        let nt_continue =
            GetProcAddress(ntdll, "NtContinue\0".as_ptr() as *const u8).unwrap() as *mut c_void;
        let rtl_capture_context = GetProcAddress(ntdll, "RtlCaptureContext\0".as_ptr() as *const u8)
            .unwrap() as *mut c_void;
        let systemfunction032 =
            GetProcAddress(advapi32, "SystemFunction032\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;

        if wait_for_single_object_ex.is_null()
            || virtual_protect.is_null()
            || set_event.is_null()
            || nt_continue.is_null()
            || rtl_capture_context.is_null()
            || systemfunction032.is_null()
        {
            println!("[-] Failed to resolve functions");
            return;
        }

        for i in 0..16 {
            key[i] = gen_random() as u8;
        }

        let mut key_buffer = USTRING {
            len: 16,
            max_len: 16,
            buffer: key.as_mut_ptr(),
        };

        let mut image = USTRING {
            len: image_size,
            max_len: image_size,
            buffer: image_base as *mut u8,
        };

        if !nt_success(NtCreateEvent(
            &mut event_timer as *mut _ as _,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) || !nt_success(NtCreateEvent(
            &mut event_start as *mut _ as _,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) || !nt_success(NtCreateEvent(
            &mut event_end as *mut _ as _,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) || !nt_success(NtCreateEvent(
            &mut event_wait as *mut _ as _,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) {
            println!("[-] Failed to create events");
            return;
        }

        println!(
            "[*] Starting Ziliean sleep obfuscation for {} milliseconds",
            time
        );

        delay += 100;
        if nt_success(RtlRegisterWait(
            &mut timer,
            event_wait,
            rtl_capture_context as *const c_void,
            &mut ctx_init as *mut AlignedContext as *const c_void,
            delay,
            WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD,
        )) {
            delay += 100;
            if nt_success(RtlRegisterWait(
                &mut timer,
                event_wait,
                set_event as *const c_void,
                event_timer as *const c_void,
                delay,
                WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
            )) {
                if !nt_success(NtWaitForSingleObject(event_timer as *mut _, 0, null_mut())) {
                    println!("[-] Failed to wait for event timer");
                    return;
                }

                let mut ctx: [AlignedContext; 7] = [ctx_init; 7];

                for i in 0..7 {
                    ctx[i].0.Rsp -= 8;
                }

                ctx[0].0.Rip = wait_for_single_object_ex as u64;
                ctx[0].0.Rcx = event_start as u64;
                ctx[0].0.Rdx = INFINITE as u64;
                ctx[0].0.R8 = 0;

                ctx[1].0.Rip = virtual_protect as u64;
                ctx[1].0.Rcx = image_base as u64;
                ctx[1].0.Rdx = image_size as u64;
                ctx[1].0.R8 = PAGE_READWRITE as u64;
                ctx[1].0.R9 = &mut old_protection as *mut u32 as u64;

                ctx[2].0.Rip = systemfunction032 as u64;
                ctx[2].0.Rcx = &mut image as *mut USTRING as u64;
                ctx[2].0.Rdx = &mut key_buffer as *mut USTRING as u64;

                ctx[3].0.Rip = wait_for_single_object_ex as u64;
                ctx[3].0.Rcx = GetCurrentProcess() as u64;
                ctx[3].0.Rdx = time as u64;
                ctx[3].0.R8 = 0;

                ctx[4].0.Rip = systemfunction032 as u64;
                ctx[4].0.Rcx = &mut image as *mut USTRING as u64;
                ctx[4].0.Rdx = &mut key_buffer as *mut USTRING as u64;

                ctx[5].0.Rip = virtual_protect as u64;
                ctx[5].0.Rcx = image_base as u64;
                ctx[5].0.Rdx = image_size as u64;
                ctx[5].0.R8 = PAGE_EXECUTE_READWRITE as u64;
                ctx[5].0.R9 = &mut old_protection as *mut _ as u64;

                ctx[6].0.Rip = set_event as u64;
                ctx[6].0.Rcx = event_end as u64;

                println!("[*] Executing sleep obfuscation chain");

                for i in 0..7 {
                    delay += 100;
                    if !nt_success(RtlRegisterWait(
                        &mut timer,
                        event_wait,
                        nt_continue as *const c_void,
                        &mut ctx[i] as *mut AlignedContext as *const c_void,
                        delay,
                        WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
                    )) {
                        println!("[-] RtlRegisterWait failed for gadget {}", i);
                        return;
                    }
                }

                println!("[+] Sleep started, waiting for {} milliseconds", time);
                if !nt_success(NtSignalAndWaitForSingleObject(
                    event_start as *mut _,
                    event_end as *mut _,
                    0,
                    null_mut(),
                )) {
                    println!("[-] Failed to wait for event end");
                    return;
                }
                println!("[*] Sleep completed");
            }
        }

        println!();

        if event_timer != null_mut() {
            CloseHandle(event_timer);
        }

        if event_wait != null_mut() {
            CloseHandle(event_wait);
        }

        if event_start != null_mut() {
            CloseHandle(event_start);
        }

        if event_end != null_mut() {
            CloseHandle(event_end);
        }
    }
}

fn main() {
    loop {
        ziliean(3000);
    }
}
