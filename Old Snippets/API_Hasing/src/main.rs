use core::arch::asm;
use std::{ffi::CStr, num::Wrapping};
use std::{os::raw::c_void, ptr::null_mut};
use winapi::{
    shared::minwindef::HINSTANCE__,
    um::winnt::{
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
        IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, IMAGE_NT_OPTIONAL_HDR_MAGIC, IMAGE_NT_SIGNATURE,
    },
};

// Hash of "USER32.DLL": 0x81E3778E
// Hash of "MessageBoxA": 0xF10E27CA

const HASH_USER32_DLL: Wrapping<u32> = Wrapping(0x81E3778E);
const HASH_MESSAGEBOXA: Wrapping<u32> = Wrapping(0xF10E27CA);

#[allow(non_camel_case_types, non_snake_case)]
type fnMessageBoxA = unsafe extern "system" fn(
    hWnd: *mut c_void,
    lpText: *const i8,
    lpCaption: *const i8,
    uType: u32,
) -> i32;

pub fn one_time_hash<T: ToString>(k: T) -> Wrapping<u32> {
    let key = k.to_string();
    let mut hash = Wrapping(0u32);
    for c in key.chars() {
        let tmp = Wrapping(c as u32);
        hash += tmp;
        hash += hash << 7;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    hash
}

unsafe fn read_gs_qword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "mov {out}, qword ptr gs:[{offset}]",
            out = out(reg) out,
            offset = in(reg) offset,
            options(nostack, preserves_flags, readonly)
        );
    }
    out
}

fn get_module_handle(hash: Wrapping<u32>) -> *mut c_void {
    unsafe {
        // dt nt!_PEB (0x60)
        let peb = read_gs_qword(0x60) as *const u8;
        if peb.is_null() {
            return null_mut();
        }

        // dt nt!_PEB_LDR_DATA (0x60 + 0x18)

        let ldr = *(peb.add(0x18) as *const *const u8);
        if ldr.is_null() {
            return null_mut();
        }

        // dt nt!_LDR_DATA_TABLE_ENTRY (0x60 + 0x18 + 0x20) => InMemoryOrderLinks

        let list_head = ldr.add(0x20);
        let mut current = *(list_head as *const *const u8);

        while !current.is_null() && current != list_head {
            // InLoadOrderModuleList is 0x10 bytes in LDR_DATA_TABLE_ENTRY
            let entry = current.sub(0x10);

            let dll_name_len = *(entry.add(0x58) as *const u16) as usize / 2;
            let base_dll_name = *(entry.add(0x60) as *const *const u16);

            if !base_dll_name.is_null() && dll_name_len != 0 {
                let dll_name_slice = std::slice::from_raw_parts(base_dll_name, dll_name_len);
                let dll_name = String::from_utf16_lossy(dll_name_slice);

                // println!("[+] DllName: {}", dll_name);

                // if dll_name.eq_ignore_ascii_case(module) {
                //     let dll_base =  *(entry.add(0x30) as *const *mut c_void);
                //     println!("[+] DllName: {}, DllName: {:p}", dll_name, dll_base);
                //     return dll_base;
                // }

                // let hash = one_time_hash(dll_name.to_uppercase().clone());

                // println!("[+] DllName: {}, Hash: 0x{:X}", dll_name, hash);

                if hash == one_time_hash(dll_name.to_uppercase().clone()) {
                    let dll_base = *(entry.add(0x30) as *const *mut c_void);
                    println!("[+] DllName: {}, DllBase: {:p}", dll_name, dll_base);
                    return dll_base;
                }
            }

            current = *(current as *const *const u8);
        }
    }

    null_mut()
}

fn get_proc_address(h_module: *mut HINSTANCE__, hash: Wrapping<u32>) -> *mut c_void {
    unsafe {
        let pbase = h_module as *const u8;

        let image_dos_header = &*(pbase as *const IMAGE_DOS_HEADER);

        if image_dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }

        let nt_header =
            &*(pbase.add(image_dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);

        if nt_header.Signature != IMAGE_NT_SIGNATURE {
            return null_mut();
        }

        let optional_header = nt_header.OptionalHeader;

        if optional_header.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            return null_mut();
        }

        let export_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_dir.VirtualAddress == 0 {
            return null_mut();
        }

        let export_dir =
            &*(pbase.add(export_data_dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY);

        let function_name_array = pbase.add(export_dir.AddressOfNames as usize) as *const u32;
        let function_address_array =
            pbase.add(export_dir.AddressOfFunctions as usize) as *const u32;
        let function_ordinal_array =
            pbase.add(export_dir.AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..export_dir.NumberOfNames {
            let name_rva = *function_name_array.add(i as usize);

            let function_name = pbase.add(name_rva as usize) as *const i8;

            let function_ordinal = *function_ordinal_array.add(i as usize) as usize;

            // let function_address = pbase.add(*(function_address_array.add(function_ordinal as usize)) as usize) as *const c_void;

            let function_rva = *function_address_array.add(function_ordinal as usize);
            let function_address = pbase.add(function_rva as usize) as *const c_void;

            // if std::ffi::CStr::from_ptr(function_name).to_str().unwrap() == dll_name {
            //     return function_address as *mut c_void;
            // }

            // if function_name.is_null() {
            //     continue;
            // }

            let fn_name = CStr::from_ptr(function_name).to_string_lossy();

            if hash == one_time_hash(fn_name.as_ref()) {
                // println!("[+] Found Function: {} - Address: {:?} - ordinal: {}", fn_name, function_address, function_ordinal);
                return function_address as *mut c_void;
            }
        }
    }
    null_mut()
}

fn main() {
    // println!("Hash of \"USER32.DLL\": 0x{:X}", one_time_hash("USER32.DLL"));
    // println!("Hash of \"MessageBoxA\": 0x{:X}", one_time_hash("MessageBoxA"));

    let h_user32 = get_module_handle(HASH_USER32_DLL);

    if h_user32.is_null() {
        println!("Failed to get module handle for user32.dll");
        return;
    }

    let func_address = get_proc_address(h_user32 as *mut HINSTANCE__, HASH_MESSAGEBOXA);

    if func_address.is_null() {
        println!("Failed to get function address for MessageBoxA");
        return;
    }

    println!("[+] MessageBoxA Address: {:p}", func_address);

    let message_box: fnMessageBoxA = unsafe { std::mem::transmute(func_address) };

    unsafe {
        message_box(
            null_mut(),
            CStr::from_bytes_with_nul(b"API Hasing!\0").unwrap().as_ptr(),
            CStr::from_bytes_with_nul(b"INFO\0").unwrap().as_ptr() as *const i8,
            0,
        );
    }
}
