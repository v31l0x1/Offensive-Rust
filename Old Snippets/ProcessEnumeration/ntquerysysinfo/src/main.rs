use std::os::raw::c_void;

use ntapi::ntexapi::{NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION};

fn get_proc_handle(process_name: &str, pid: *mut u32, process_handle: &mut *mut c_void) -> bool {
    
    let mut return_length: u32 = 0;

    unsafe {
        // First call to get the required buffer size
        NtQuerySystemInformation(
            5,  // SystemProcessInformation
            std::ptr::null_mut(), 
            0, 
            &mut return_length 
        );

        if return_length == 0 {
            println!("[-] Failed to get required buffer size");
            return false;
        }

        // Allocate a buffer large enough for all process information
        let mut buffer = vec![0u8; return_length as usize];

        let status = NtQuerySystemInformation(
            5,  // SystemProcessInformation
            buffer.as_mut_ptr() as *mut ntapi::winapi::ctypes::c_void,
            return_length, 
            &mut return_length 
        );
        if status != 0x0 {
            println!("[-] NtQuerySystemInformation failed with status: 0x{:X}", status);
            return false;
        }

        // Iterate through the linked list of process information
        let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            let proc_info = &*current_ptr;

            // Check if ImageName is valid (UTF-16 wide string)
            if !proc_info.ImageName.Buffer.is_null() && proc_info.ImageName.Length > 0 {
                let len_chars = proc_info.ImageName.Length as usize / 2;
                if len_chars > 0 && len_chars < 4096 {
                    let wide_str = std::slice::from_raw_parts(
                        proc_info.ImageName.Buffer as *const u16,
                        len_chars
                    );
                    let image_name = String::from_utf16_lossy(wide_str);
                    
                    if process_name.eq_ignore_ascii_case(&image_name) {
                        *pid = proc_info.UniqueProcessId as u32;
                        *process_handle = proc_info.HandleCount as *mut c_void;
                        return true;
                    }
                }
            }

            if proc_info.NextEntryOffset == 0 {
                break;
            }

            // Move to the next process entry
            current_ptr = (current_ptr as *const u8)
                .add(proc_info.NextEntryOffset as usize) 
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    false
}

fn main() {

    let process_name = "notepad.exe";
    let mut pid: u32 = 0;
    let mut process_handle: *mut c_void = std::ptr::null_mut();

    let status = get_proc_handle(process_name, &mut pid, &mut process_handle);
    if status {
        println!("[+] Found process '{}' with PID: {} and Handle: 0x{:X}", process_name, pid, process_handle as usize);
    } else {
        println!("[-] Failed to find process '{}'.", process_name);
    }

}
