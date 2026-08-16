use std::{mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
            GetThreadContext, SetThreadContext,
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Threading::GetCurrentThread,
    },
};

unsafe extern "system" {
    fn NtTraceEvent(
        TraceHandle: *mut c_void,
        Flags: u32,
        FieldSize: u32,
        Fields: *mut c_void,
    ) -> i32;
}

static mut NT_TRACE_EVENT_ADDR: *mut c_void = null_mut();

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
            if (*(*exception_info).ExceptionRecord).ExceptionAddress == NT_TRACE_EVENT_ADDR {
                println!(
                    "[+] VEH Triggered: NtTraceEvent: {:?}",
                    (*(*exception_info).ExceptionRecord).ExceptionAddress
                );

                (*(*exception_info).ContextRecord).Rax = 0;
                (*(*exception_info).ContextRecord).Rip =
                    *((*(*exception_info).ContextRecord).Rsp as *const u64);
                (*(*exception_info).ContextRecord).Rsp += size_of::<*mut c_void>() as u64;

                (*(*exception_info).ContextRecord).EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

fn main() {
    unsafe {
        let h_ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);

        if h_ntdll.is_null() {
            println!("[-] Failed to get handle to ntdll.dll");
            return;
        }
        println!("[+] Found ntdll.dll at: {:?}", h_ntdll);

        let nt_trace_event =
            GetProcAddress(h_ntdll, "NtTraceEvent\0".as_ptr() as *const u8).unwrap() as *mut c_void;

        if nt_trace_event.is_null() {
            println!("[-] Failed to get address of NtTraceEvent");
            return;
        }

        NT_TRACE_EVENT_ADDR = nt_trace_event;
        println!("[+] Found NtTraceEvent at: {:?}", nt_trace_event);

        AddVectoredExceptionHandler(1, Some(exception_handler));

        set_hwbp(GetCurrentThread(), nt_trace_event, 0);

        NtTraceEvent(null_mut(), 0, 0, null_mut());

        rm_hwbp(GetCurrentThread(), 0);
    }
}
