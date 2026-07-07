#[allow(deprecated)]
use std::{intrinsics::copy_nonoverlapping, mem::zeroed};

use winapi::{
    ctypes::c_void,
    shared::windef::HWND,
    um::{
        errhandlingapi::GetLastError,
        memoryapi::VirtualProtect,
        winnt::PAGE_EXECUTE_READWRITE,
        winuser::{MB_OK, MessageBoxA, MessageBoxW},
    },
};

struct HookSt {
    // PVOID
    pfunctiontohook: *mut c_void,
    pfunctiontorun: *mut c_void,
    poriginalbytes: [u8; 13],
    dwoldprotection: u32,
}

fn install_hook(hook: &mut HookSt) -> bool {
    let mut trampoline: [u8; 13] = [
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pfunctiontorun
        0x41, 0xFF, 0xE2, // jmp r10
    ];

    // Fill in the 64-bit address of pfunctiontorun
    let addr_bytes = (hook.pfunctiontorun as u64).to_le_bytes();
    for i in 0..8 {
        trampoline[2 + i] = addr_bytes[i];
    }

    let patch = hook.pfunctiontohook as *mut u8;

    unsafe {
        let mut oldprotection: u32 = 0;

        // Make memory executable and writable
        if VirtualProtect(
            hook.pfunctiontohook,
            13,
            PAGE_EXECUTE_READWRITE,
            &mut oldprotection,
        ) == 0
        {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return false;
        }

        // Write trampoline to the hooked function
        copy_nonoverlapping(trampoline.as_ptr(), patch, 13);

        // Restore original protection
        if VirtualProtect(hook.pfunctiontohook, 13, oldprotection, &mut oldprotection) == 0 {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return false;
        }
    }

    true
}

fn remove_hook(hook: &mut HookSt) -> bool {
    let mut oldprotection: u32 = 0;

    unsafe {
        // Make memory writable
        if VirtualProtect(
            hook.pfunctiontohook,
            13,
            PAGE_EXECUTE_READWRITE,
            &mut oldprotection,
        ) == 0
        {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return false;
        }

        // Restore original bytes
        copy_nonoverlapping(
            hook.poriginalbytes.as_ptr(),
            hook.pfunctiontohook as *mut u8,
            13,
        );

        // Restore original protection
        if VirtualProtect(
            hook.pfunctiontohook,
            13,
            hook.dwoldprotection,
            &mut oldprotection,
        ) == 0
        {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return false;
        }

        hook.pfunctiontohook = std::ptr::null_mut();
        hook.pfunctiontorun = std::ptr::null_mut();
        hook.dwoldprotection = 0;
    }

    true
}


fn initial_hook(
    pfunctiontohook: *mut c_void,
    pfunctiontorun: *mut c_void,
    hook: &mut HookSt,
) -> bool {
    hook.pfunctiontohook = pfunctiontohook;
    hook.pfunctiontorun = pfunctiontorun;

    unsafe {
        let mut oldprotection: u32 = 0;

        // Make memory accessible first
        if VirtualProtect(
            pfunctiontohook,
            13,
            PAGE_EXECUTE_READWRITE,
            &mut oldprotection,
        ) == 0
        {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return false;
        }

        // Save the old protection for later restoration
        hook.dwoldprotection = oldprotection;

        // Save the original bytes
        copy_nonoverlapping(
            pfunctiontohook as *const u8,
            hook.poriginalbytes.as_mut_ptr(),
            13,
        );
    }

    true
}

fn my_meesagebox() {
    println!("[+] Hooked MessageBoxA called!");
    unsafe {

        let text: Vec<u16> = "Hooked MessageBoxA\0".encode_utf16().collect();
        let Caption: Vec<u16> = "HOOK\0".encode_utf16().collect();

        MessageBoxW(HWND::default(), text.as_ptr(), Caption.as_ptr(), MB_OK);
    }
}

fn main() {
    unsafe {
        let mut hook: HookSt = zeroed::<HookSt>();

        if !initial_hook(
            MessageBoxA as *mut c_void,
            my_meesagebox as *mut c_void,
            &mut hook,
        ) {
            println!("[-] Failed to initialize hook");
            return;
        }

        MessageBoxA(
            HWND::default(),
            String::from("Before Hooking\0").as_ptr() as *const i8,
            String::from("HOOK\0").as_ptr() as *const i8,
            MB_OK,
        );

        if !install_hook(&mut hook) {
            println!("[-] Failed to install hook");
            return;
        }

        MessageBoxA(
            HWND::default(),
            String::from("After Hooking\0").as_ptr() as *const i8,
            String::from("HOOK\0").as_ptr() as *const i8,
            MB_OK,
        );

        if !remove_hook(&mut hook) {
            println!("[-] Failed to remove hook");
            return;
        }

        MessageBoxA(
            HWND::default(),
            String::from("After Removing Hook\0").as_ptr() as *const i8,
            String::from("HOOK\0").as_ptr() as *const i8,
            MB_OK,
        );
    }
}
