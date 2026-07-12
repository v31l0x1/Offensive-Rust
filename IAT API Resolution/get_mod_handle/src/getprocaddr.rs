#![allow(non_camel_case_types, unused, non_snake_case)]

use std::ptr::null_mut;

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
type IMAGE_SUBSYSTEM = u16;
type IMAGE_DLL_CHARACTERISTICS = u16;
type PVOID = *mut std::ffi::c_void;

#[repr(C, packed(4))]
struct IMAGE_OPTIONAL_HEADER {
    Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: IMAGE_SUBSYSTEM,
    DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,    // RVA from base of image
    AddressOfNames: u32,        // RVA from base of image
    AddressOfNameOrdinals: u32, // RVA from base of image
}

pub fn getprocaddr(h_module: PVOID, func_name: &str) -> PVOID {
    let base_address = h_module as *const u8;
    let dos_header = base_address as *const IMAGE_DOS_HEADER;

    let nt_headers =
        unsafe { base_address.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS };

    let export_directory_rva =
        unsafe { (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress };
    if export_directory_rva == 0 {
        return null_mut();
    }

    let export_directory =
        unsafe { base_address.add(export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY };

    let address_of_names =
        unsafe { base_address.add((*export_directory).AddressOfNames as usize) as *const u32 };
    let address_of_functions =
        unsafe { base_address.add((*export_directory).AddressOfFunctions as usize) as *const u32 };
    let address_of_name_ordinals = unsafe {
        base_address.add((*export_directory).AddressOfNameOrdinals as usize) as *const u16
    };

    unsafe {
        for i in 0..(*export_directory).NumberOfNames {
            let name_rva = unsafe { *address_of_names.add(i as usize) };
            let function_name = unsafe { base_address.add(name_rva as usize) as *const i8 };

            let c_str = std::ffi::CStr::from_ptr(function_name);
            if let Ok(name) = c_str.to_str() {
                if name == func_name {
                    let ordinal = unsafe { *address_of_name_ordinals.add(i as usize) } as usize;
                    let function_rva = unsafe { *address_of_functions.add(ordinal) };

                    println!("Found function: {} at RVA: 0x{:X}", name, function_rva);
                    return unsafe { base_address.add(function_rva as usize) as PVOID };
                }
            }
        }
    }

    null_mut()
}
