use std::mem::size_of;
use winapi::{
    ctypes::c_void, shared::minwindef::HMODULE, um::{
        errhandlingapi::GetLastError, handleapi::CloseHandle, processthreadsapi::OpenProcess, psapi::{EnumProcessModules, EnumProcesses, GetModuleBaseNameA}, winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ}
    }
};

#[allow(dead_code)]
fn get_remote_process_handle(procname: &str, procpid: &mut u32, prochandle: &mut *mut c_void) -> bool {
    let mut processes: Vec<u32> = vec![0; 1024];
    let mut bytes_returned: u32 = 0;
    let mut module_handle: HMODULE = std::ptr::null_mut();
    let mut process_name = [0u8; 256];

    unsafe {
        let status = EnumProcesses(processes.as_mut_ptr(), (processes.len() * size_of::<u32>()) as u32, &mut bytes_returned);

        if status == 0 {
            println!("[-] EnumProcesses failed with error: {}", GetLastError());
            return false;
        }
    }

    let process_count = (bytes_returned as usize) / size_of::<u32>();
    processes.truncate(process_count);

    println!("[+] Number of processes: {}", process_count);

    unsafe {
        for pid in 0..process_count {
            if processes[pid] == 0 {
                continue;
            }

            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, processes[pid]);
            if process_handle == std::ptr::null_mut() {
                continue;
            }

            let mut module_bytes_returned: u32 = 0;
            let status = EnumProcessModules(
                process_handle,
                &mut module_handle,
                size_of::<HMODULE>() as u32,
                &mut module_bytes_returned,
            );

            if status == 0 {
                println!("[-] EnumProcessModules Failed [At Pid: {}] with error: {}", processes[pid], GetLastError());
                CloseHandle(process_handle);
                continue;
            }

            let status = GetModuleBaseNameA(
                process_handle,
                module_handle,
                process_name.as_mut_ptr() as *mut i8,
                process_name.len() as u32,
            );

            if status == 0 {
                println!("[-] GetModuleBaseNameA Failed [At Pid: {}] with error: {}", processes[pid], GetLastError());
                CloseHandle(process_handle);
                continue;
            }

            let process_name_len = process_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(process_name.len());
            let process_name_str = String::from_utf8_lossy(&process_name[..process_name_len]).to_string();

            if process_name_str.eq_ignore_ascii_case(procname) {
                *procpid = processes[pid];
                *prochandle = process_handle;
                return true;
            }

            CloseHandle(process_handle);
        }
    }

    false
}


#[allow(dead_code)]
fn printprocesses() -> bool {
    let mut processes: Vec<u32> = vec![0; 1024];
    let mut bytes_returned: u32 = 0;
    let mut module_handle: HMODULE = std::ptr::null_mut();
    let mut process_name = [0u8; 256];

    unsafe {
        let status = EnumProcesses(
            processes.as_mut_ptr(),
            (processes.len() * size_of::<u32>()) as u32,
            &mut bytes_returned,
        );

        if status == 0 {
            println!("[-] EnumProcesses failed with error: {}", GetLastError());
            return false;
        }
    }

    let process_count = (bytes_returned as usize) / size_of::<u32>();
    processes.truncate(process_count);

    println!("[+] Number of processes: {}", process_count);

    unsafe {
        for pid in 0..process_count {
            if processes[pid] != 0 {
                let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, processes[pid]);
                if process_handle != std::ptr::null_mut() {

                    let mut module_bytes_returned: u32 = 0;
                    let status = EnumProcessModules(
                        process_handle,
                        &mut module_handle,
                        size_of::<HMODULE>() as u32,
                        &mut module_bytes_returned,
                    );

                    if status == 0 {
                        println!("[-] EnumProcessModules Failed [At Pid: {}] with error: {}", processes[pid], GetLastError());
                    } else {

                        let status = GetModuleBaseNameA(
                            process_handle,
                            module_handle,
                            process_name.as_mut_ptr() as *mut i8,
                            process_name.len() as u32,
                        );

                        if status == 0 {
                            println!("[-] GetModuleBaseNameA Failed [At Pid: {}] with error: {}", processes[pid], GetLastError());
                        } else {
                            let process_name_len = process_name
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(process_name.len());
                            let process_name_str = String::from_utf8_lossy(&process_name[..process_name_len]);
                            println!("[+] PID: {} - Process Name: {}", processes[pid], process_name_str);
                        }

                    }

                }
            }
        }
    }
    true
}

fn main() {
    // let status = printprocesses();

    // if status == false {
    //     println!("[-] Failed to print processes.");
    // }

    let process_name = "notepad.exe";
    let mut process_id: u32 = 0;
    let mut process_handle: *mut c_void = std::ptr::null_mut();

    let status = get_remote_process_handle(process_name, &mut process_id, &mut process_handle);
    if !status {
        println!("[-] Failed to get handle for process: {}", process_name);
    } else {
        println!("[+] Successfully obtained handle for process: {} with PID: {}", process_name, process_id);
    }
}
