#![allow(non_snake_case, deprecated)]
use std::{mem::transmute, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    System::LibraryLoader::{GetProcAddress, LoadLibraryA},
    UI::WindowsAndMessaging::MessageBoxW,
};

use min_hook_rs::*;

type MessageBoxAFn = unsafe extern "system" fn(
    hwnd: *mut c_void,
    lptext: *const u8,
    lpcaption: *const u8,
    utype: u32,
) -> i32;

unsafe extern "system" fn HookedMessageBoxA(
    hwnd: *mut c_void,
    _lptext: *const u8,
    _lpcaption: *const u8,
    utype: u32,
) -> i32 {
    println!("[+] Hooked MessageBoxA called!");
    unsafe {
        let text: Vec<u16> = "Hooked MessageBoxA called!\0".encode_utf16().collect();
        let caption: Vec<u16> = "Hooked\0".encode_utf16().collect();
        MessageBoxW(hwnd, text.as_ptr(), caption.as_ptr(), utype);
    }
    0
}

fn main() {
    unsafe {
        initialize().unwrap();

        let user32 = LoadLibraryA("user32.dll\0".as_ptr());

        if user32.is_null() {
            println!("[-] Failed to load user32.dll");
            return;
        }

        println!("[+] user32.dll :{:?}", user32);

        let message_box: *const c_void =
            GetProcAddress(user32, "MessageBoxA\0".as_ptr()).unwrap() as *const c_void;

        println!("[+] MessageBoxA: {:?}", message_box);
        let message_box: MessageBoxAFn = transmute(message_box);

        let _trampoline =
            create_hook(message_box as *mut c_void, HookedMessageBoxA as *mut c_void).unwrap();

        enable_hook(message_box as *mut c_void).unwrap();

        message_box(
            null_mut(),
            "Hello from Rust!\0".as_ptr(),
            "Rust MessageBox\0".as_ptr(),
            0,
        );

        disable_hook(message_box as *mut c_void).unwrap();

        message_box(
            null_mut(),
            "Hello from Rust!\0".as_ptr(),
            "Rust MessageBox\0".as_ptr(),
            0,
        );
    }
}
