use windows::{
    core::s,
    Win32::{
        Foundation::{HINSTANCE, HWND},
        System::SystemServices::{
            DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
        },
        UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
    },
};

#[unsafe(no_mangle)]
pub extern "C" fn hello_world() {
    unsafe {
        MessageBoxA(Some(HWND::default()), s!("Hello from Function"), s!("INFO"), MB_OK);
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            MessageBoxA(
                Some(HWND::default()),
                s!("DLL Message"),
                s!("DLL Message"),
                MB_OK,
            );
        },
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    };

    true
}