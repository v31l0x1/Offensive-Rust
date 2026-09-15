#![allow(non_snake_case)]
use std::{ffi::CStr, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    System::{
        Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64},
        LibraryLoader::{GetModuleHandleA, LoadLibraryA},
        Memory::{PAGE_READWRITE, VirtualProtect},
        SystemServices::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
        },
    },
    UI::WindowsAndMessaging::{MB_OK, MessageBoxA, MessageBoxW},
};

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

struct IATHook {
    base_addr: *const u8,
    dll_name: String,
    func_name: String,
    hooked_func: *const c_void,
    org_entry: *const c_void,
}

fn iat_patch(iat_hook: *mut IATHook) -> bool {
    unsafe {
        let hmodule = (*iat_hook).base_addr as *const c_void;
        let dos_header = hmodule as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return false;
        }

        let nt_headers = (hmodule as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header");
            return false;
        }

        let import_directory =
            (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        if import_directory.VirtualAddress == 0 {
            println!("[-] No import directory found");
            return false;
        }

        let mut import_desc = (hmodule as *const u8).add(import_directory.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        loop {
            if (*import_desc).Name == 0 {
                break;
            }

            let dll_name_ptr =
                (hmodule as *const u8).add((*import_desc).Name as usize) as *const i8;

            let dll_name = match CStr::from_ptr(dll_name_ptr).to_str() {
                Ok(name) => name,
                Err(_) => {
                    import_desc = import_desc.add(1);
                    continue;
                }
            };

            // println!("[*] Import: {}", dll_name);

            if dll_name.eq_ignore_ascii_case(&(*iat_hook).dll_name) {
                println!("[+] Found target DLL: {}", dll_name);

                let mut thunk =
                    (hmodule as *const u8).add((*import_desc).FirstThunk as usize) as *mut usize;
                let mut name_thunk = (hmodule as *const u8)
                    .add((*import_desc).Anonymous.Characteristics as usize)
                    as *mut usize;

                loop {
                    if (*name_thunk) == 0 {
                        break;
                    }

                    if (*name_thunk) & (1 << 63) == 0 {
                        let name_rva = (*name_thunk) as usize;
                        let import_by_name = (hmodule as *const u8).add(name_rva + 2) as *const u8;
                        let func_name = CStr::from_ptr(import_by_name as *const i8)
                            .to_str()
                            .unwrap_or("");

                        // println!("[*] Imported function: {}", func_name);

                        if func_name.eq_ignore_ascii_case(&(*iat_hook).func_name) {
                            println!("[+] Found target function: {}", func_name);

                            let mut old_protect: u32 = 0;
                            VirtualProtect(
                                thunk as *const c_void,
                                8,
                                PAGE_READWRITE,
                                &mut old_protect,
                            );

                            let original_func = *thunk as *mut usize;
                            (*iat_hook).org_entry = original_func as *const c_void;
                            *thunk = (*iat_hook).hooked_func as usize;
                            VirtualProtect(
                                thunk as *const c_void,
                                8,
                                old_protect,
                                &mut old_protect,
                            );
                            return true;
                        }
                    }

                    thunk = thunk.add(1);
                    name_thunk = name_thunk.add(1);
                }

                return true;
            }

            import_desc = import_desc.add(1);
        }
    }

    true
}

fn main() {
    unsafe {
        let mut iat_hook = IATHook {
            base_addr: null_mut(),
            dll_name: "user32.dll".to_string(),
            func_name: "MessageBoxA".to_string(),
            hooked_func: null_mut(),
            org_entry: null_mut(),
        };
        let user32 = LoadLibraryA("user32.dll\0".as_ptr());

        if user32.is_null() {
            println!("[-] Failed to load user32.dll");
            return;
        }

        let base_address = GetModuleHandleA(null_mut());

        iat_hook.base_addr = base_address as *const u8;
        iat_hook.hooked_func = HookedMessageBoxA as *const c_void;

        iat_patch(&mut iat_hook);

        MessageBoxA(
            null_mut(),
            "Hello, World!\0".as_ptr(),
            "Test\0".as_ptr(),
            MB_OK,
        );
    }
}
