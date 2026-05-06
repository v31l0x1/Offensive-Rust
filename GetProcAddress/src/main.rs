use std::ptr::{null, null_mut};

use winapi::{ctypes::c_void, shared::minwindef::{HINSTANCE, HINSTANCE__}, um::{errhandlingapi::GetLastError, libloaderapi::GetModuleHandleA, winnt::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, IMAGE_NT_OPTIONAL_HDR_MAGIC, IMAGE_NT_SIGNATURE, IMAGE_OPTIONAL_HEADER, PIMAGE_EXPORT_DIRECTORY}}};




fn get_proc_address(h_module: *mut HINSTANCE__, dll_name: &str) -> *mut c_void {

    unsafe {
        let pbase = h_module as *const u8;

        let image_dos_header = &*(pbase as *const IMAGE_DOS_HEADER);

        if image_dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }

        let nt_header = &*(pbase.add(image_dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);

        if nt_header.Signature != IMAGE_NT_SIGNATURE {
            return null_mut();
        }

        let optional_header = nt_header.OptionalHeader;

        if optional_header.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            return null_mut();
        }

        let export_data_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        let export_dir = &*(pbase.add(export_data_dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY);

        let function_name_array = pbase.add(export_dir.AddressOfNames as usize) as *const u32;
        let function_address_array = pbase.add(export_dir.AddressOfFunctions as usize) as *const u32;
        let function_ordinal_array = pbase.add(export_dir.AddressOfNameOrdinals as usize) as *const u16;


        for i in 0..export_dir.NumberOfFunctions {

            let name_rva = *function_name_array.add(i as usize);

            let function_name = pbase.add(name_rva as usize) as *const i8;

            let function_ordinal = *function_ordinal_array.add(i as usize) as usize;

            // let function_address = pbase.add(*(function_address_array.add(function_ordinal as usize)) as usize) as *const c_void;
            
            let function_rva = *function_address_array.add(function_ordinal as usize);            
            let function_address = pbase.add(function_rva as usize) as *const c_void;

            // println!("[ {:04} ] Function: {:?} - Address: {:?} - ordinal: {}", i, std::ffi::CStr::from_ptr(function_name), function_address, function_ordinal);


            if std::ffi::CStr::from_ptr(function_name).to_str().unwrap() == dll_name {
                return function_address as *mut c_void;
            }

        }

    }


    null_mut()
}


fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {


    unsafe {
        let h_kernel32 = GetModuleHandleA("kernel32.dll\0".to_string().as_ptr() as *const i8);

        if h_kernel32.is_null() {
            println!("[-] GetModuleHandleA failed with error: {}", GetLastError());
            return;
        }

        println!("[+] Found kernel32.dll at address: {:?}", h_kernel32);


        let pVirtualAlloc = get_proc_address(h_kernel32, "VirtualAlloc");

        
        if pVirtualAlloc.is_null() {
            println!("[-] Failed to resolve VirtualAlloc");
            return;
        }   

        println!("[+] Resolved VirtualAlloc at address: {:?}", pVirtualAlloc);
        
        pause();


    }
}