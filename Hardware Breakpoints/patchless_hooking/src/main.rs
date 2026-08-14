use std::{mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::{EXCEPTION_SINGLE_STEP, HWND},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
            GetThreadContext, SetThreadContext,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Threading::GetCurrentThread,
    },
    UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
};

static mut MESSAGEBOX_ADDR: *mut c_void = null_mut();

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

        // let local_enable_bit = 1u64 << (reg_index * 2); // L0/L1/L2/L3
        // let rw_shift = 16 + (reg_index as u64 * 4); // R/W bits
        // let len_shift = 18 + (reg_index as u64 * 4); // LEN bits

        // context.Dr7 |= local_enable_bit;
        // context.Dr7 &= !(0x3u64 << rw_shift); // R/W = 00 (execute)
        // context.Dr7 &= !(0x3u64 << len_shift); // LEN = 00 (1 byte)

        context.Dr7 |= 1u64 << (reg_index * 2); // Enable the breakpoint
        context.Dr7 &= !(0x3u64 << (16 + reg_index as u64 * 4)); // Set the breakpoint to trigger on execution
        context.Dr7 &= !(0x3u64 << (18 + reg_index as u64 * 4)); // Set the breakpoint size to 1 byte

        if SetThreadContext(thread_handle, &mut context) == 0 {
            return false;
        }
    }

    true
}

unsafe extern "system" fn exception_handler(exceptioninfo: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if (*(*exceptioninfo).ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
            if (*(*exceptioninfo).ExceptionRecord).ExceptionAddress == MESSAGEBOX_ADDR {
                println!("Hardware breakpoint hit!");

                println!("RCX: {:X}", (*(*exceptioninfo).ContextRecord).Rcx);
                println!("RDX: {:X}", (*(*exceptioninfo).ContextRecord).Rdx);
                println!("R8: {:X}", (*(*exceptioninfo).ContextRecord).R8);
                println!("R9: {:X}", (*(*exceptioninfo).ContextRecord).R9);

                let return_address = (*exceptioninfo).ContextRecord.read().Rip;
                println!("Return address: {:X}", return_address);

                (*exceptioninfo).ContextRecord.read().Rdx = "Hooked\0".as_ptr() as u64;

                // Set the Resume Flag (RF) to prevent re-triggering the breakpoint
                (*(*exceptioninfo).ContextRecord).EFlags |= 0x10000;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

fn main() {
    unsafe {
        let user32 = LoadLibraryA("user32.dll\0".as_ptr() as *const u8);

        println!("user32.dll loaded at: {:p}", user32);

        let messagebox_addr =
            GetProcAddress(user32, "MessageBoxA\0".as_ptr() as *const u8).unwrap() as *mut c_void;
        println!("MessageBoxA address: {:p}", messagebox_addr);
        MESSAGEBOX_ADDR = messagebox_addr;

        AddVectoredExceptionHandler(1, Some(exception_handler));
        set_hwbp(GetCurrentThread(), messagebox_addr, 0);

        MessageBoxA(
            HWND::default(),
            "Normal Message\0".as_ptr() as *const u8,
            "INFO\0".as_ptr() as *const u8,
            MB_OK,
        );
    }
}
