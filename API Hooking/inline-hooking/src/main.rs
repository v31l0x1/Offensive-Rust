use std::{
    intrinsics::copy_nonoverlapping,
    mem::{transmute, zeroed},
    os::raw::c_void,
    ptr::null_mut,
};

use windows_sys::Win32::{
    System::{
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
    },
    UI::WindowsAndMessaging::{MessageBoxA, MessageBoxW},
};

type MessageBoxAFn = unsafe extern "system" fn(
    hwnd: *mut c_void,
    lptext: *const u8,
    lpcaption: *const u8,
    utype: u32,
) -> i32;

struct Hook {
    pfunctiontohook: *const c_void,
    pfunctiontorun: *const c_void,
    poriginalbytes: [u8; 13],
    dwoldprotection: u32,
}

fn install_hook(hook: &mut Hook) -> bool {
    unsafe {
        let patch = hook.pfunctiontohook as *mut u8;
        let mut old_protect: u32 = 0;

        if VirtualProtect(
            hook.pfunctiontohook,
            13,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            return false;
        }

        copy_nonoverlapping(patch, hook.poriginalbytes.as_mut_ptr(), 13);
        hook.dwoldprotection = old_protect;

        let mut patch_bytes: [u8; 13] = [0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xFF, 0xE2];

        let addr_bytes = (hook.pfunctiontorun as usize).to_le_bytes();
        patch_bytes[2..10].copy_from_slice(&addr_bytes);

        copy_nonoverlapping(patch_bytes.as_ptr(), patch, 13);

        VirtualProtect(hook.pfunctiontohook, 13, old_protect, &mut old_protect);
    }
    true
}

fn rm_hook(hook: &mut Hook) -> bool {
    unsafe {
        let patch = hook.pfunctiontohook as *mut u8;

        let mut old_protect: u32 = 0;
        if VirtualProtect(
            hook.pfunctiontohook,
            13,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection");
            return false;
        }

        copy_nonoverlapping(hook.poriginalbytes.as_ptr(), patch, 13);

        if VirtualProtect(hook.pfunctiontohook, 13, old_protect, &mut old_protect) == 0 {
            println!("[-] Failed to restore memory protection");
            return false;
        }

        hook.pfunctiontohook = null_mut();
        hook.poriginalbytes = [0; 13];
        hook.pfunctiontorun = null_mut();
        hook.dwoldprotection = 0;
    }
    true
}

unsafe extern "system" fn HookedMessageBoxA(
    hwnd: *mut c_void,
    lptext: *const u8,
    lpcaption: *const u8,
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
        let mut hook: Hook = zeroed::<Hook>();

        let user32 = LoadLibraryA("user32.dll\0".as_ptr());
        if user32.is_null() {
            println!("[-] Failed to load user32.dll");
            return;
        }

        println!("[+] user32.dll :{:?}", user32);

        let message_box: *const c_void =
            GetProcAddress(user32, "MessageBoxA\0".as_ptr()).unwrap() as *const c_void;

        println!("[+] MessageBoxA: {:?}", message_box);

        hook.pfunctiontohook = message_box;
        hook.pfunctiontorun = HookedMessageBoxA as *const c_void;

        if !install_hook(&mut hook) {
            println!("[-] Failed to install hook");
            return;
        }

        let message_box: MessageBoxAFn = transmute(message_box);

        message_box(
            null_mut(),
            "Hello from Rust!\0".as_ptr(),
            "Rust MessageBox\0".as_ptr(),
            0,
        );

        if !rm_hook(&mut hook) {
            println!("[-] Failed to remove hook");
            return;
        }

        message_box(
            null_mut(),
            "Hello from Rust!\0".as_ptr(),
            "Rust MessageBox\0".as_ptr(),
            0,
        );
    }
}
