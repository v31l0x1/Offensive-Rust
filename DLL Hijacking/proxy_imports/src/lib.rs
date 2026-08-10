#![allow(non_snake_case)]
use std::os::raw::c_void;

use windows_sys::Win32::{
    Foundation::HWND,
    System::SystemServices::{
        DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
    },
    UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
};

/*
    node.exe imports timeGetTime() function from WINMM.dll .
*/

#[unsafe(no_mangle)]
pub unsafe extern "system" fn timeGetTime() {}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _h_instance: *mut c_void,
    call_reason: u32,
    _reserved: *mut c_void,
) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            MessageBoxA(
                HWND::default(),
                "DLL Injection!\0".as_ptr() as *mut u8,
                "INFO\0".as_ptr() as *mut u8,
                MB_OK,
            );
        },
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    }

    true
}
