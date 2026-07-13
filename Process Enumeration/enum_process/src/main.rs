use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        ProcessStatus::{EnumProcesses, GetModuleBaseNameA},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

fn find_pid(proc_name: &str) -> u32 {
    unsafe {
        let mut processes: [u32; 1024] = [0; 1024];
        let mut cb = 0;

        if EnumProcesses(
            processes.as_mut_ptr(),
            1024 * std::mem::size_of::<u32>() as u32,
            &mut cb,
        ) == 0
        {
            println!("[-] Failed to enumerate processes.");
            return 0;
        }

        let proc_count = cb / std::mem::size_of::<u32>() as u32;

        for i in 0..proc_count as usize {
            let process_handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 1, processes[i]);

            if process_handle.is_null() {
                continue;
            }

            let mut buffer: [u8; 260] = [0; 260];

            if GetModuleBaseNameA(
                process_handle,
                std::ptr::null_mut(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            ) != 0
            {
                if let Ok(name) = std::ffi::CStr::from_ptr(buffer.as_ptr() as *const i8).to_str() {
                    if name.eq_ignore_ascii_case(proc_name) {
                        return processes[i];
                    }
                }
            }

            CloseHandle(process_handle);
        }
    }

    0
}

fn main() {
    let proc_name = "notepad.exe".to_string();

    let pid = find_pid(&proc_name);

    if pid != 0 {
        println!("Process ID of {}: {}", proc_name, pid);
    } else {
        println!("Process {} not found.", proc_name);
    }
}
