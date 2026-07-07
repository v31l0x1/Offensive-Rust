use std::{
    mem::{zeroed},
    ptr::{null_mut},
};

use winapi::{
    shared::{
        minwindef::{LPARAM, LRESULT, WPARAM},
        ntdef::NULL,
        windef::HHOOK,
    },
    um::{
        errhandlingapi::GetLastError,
        processthreadsapi::CreateThread,
        synchapi::WaitForSingleObject,
        winuser::{
            CallNextHookEx, DefWindowProcW, GetMessageW, MSG, SetWindowsHookExW, UnhookWindowsHookEx, WH_MOUSE_LL, WM_LBUTTONDOWN, WM_RBUTTONDOWN
        },
    },
};

static mut G_MOUSEHOOK: HHOOK = NULL as HHOOK;

#[allow(warnings)]
unsafe extern "system" fn hook_callback(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if wparam == WM_LBUTTONDOWN as usize {
        println!("[+] Left Mouse Click");
        // let text: Vec<u16> = "Left Mouse Click\0".encode_utf16().collect();
        // let caption: Vec<u16> = "Mouse Tracker\0".encode_utf16().collect();
        // MessageBoxW(null_mut(), text.as_ptr(), caption.as_ptr(), 0);
    }

    if wparam == WM_RBUTTONDOWN as usize {
        println!("[+] Right Mouse Click");
        // let text: Vec<u16> = "Right Mouse Click\0".encode_utf16().collect();
        // let caption: Vec<u16> = "Mouse Tracker\0".encode_utf16().collect();
        // MessageBoxW(null_mut(), text.as_ptr(), caption.as_ptr(), 0);
    }

    CallNextHookEx(null_mut(), ncode, wparam, lparam)
}


#[allow(warnings)]
unsafe extern "system" fn tracker_mouse(_: *mut winapi::ctypes::c_void) -> u32 {
    let mut msg: MSG = zeroed::<MSG>();

    G_MOUSEHOOK = SetWindowsHookExW(WH_MOUSE_LL, Some(hook_callback), null_mut(), 0);

    if G_MOUSEHOOK.is_null() {
        println!(
            "[-] SetWindowsHookExW failed with error: {}",
            GetLastError()
        );
        return 0;
    }

    while GetMessageW(&mut msg, null_mut(), 0, 0) != 0 {
        DefWindowProcW(msg.hwnd, msg.message, msg.wParam, msg.lParam);
    }

    return 1;
}

fn main() {
    unsafe {
        let hthread = CreateThread(
            null_mut(),
            0,
            Some(tracker_mouse),
            null_mut(),
            0,
            null_mut(),
        );

        if hthread.is_null() {
            println!("[-] CreateThread failed with error: {}", GetLastError());
            return;
        }

        WaitForSingleObject(hthread, 10000);

        if !G_MOUSEHOOK.is_null() && UnhookWindowsHookEx(G_MOUSEHOOK) == 0 {
            println!(
                "[-] UnhookWindowsHookEx failed with error: {}",
                GetLastError()
            );
        }
    }
}
